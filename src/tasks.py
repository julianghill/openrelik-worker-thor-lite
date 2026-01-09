# Copyright 2025 Nextron Systems GmbH

import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from typing import Final
import zipfile

from celery.utils.log import get_task_logger

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import (
    create_task_result,
    get_input_files,
)

from .app import celery

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-thor-lite.tasks.thor-lite"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "Thor Lite",
    "description": "Scanner for attacker tools and activity",
    "task_config": [
        {
            "name": "update_signatures",
            "label": "Update signatures before scan",
            "description": "Fetch the latest THOR Lite signatures before running the scan.",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "json_v2",
            "label": "Use JSON v2 output",
            "description": "Enable THOR JSON v2 format for easier parsing.",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "custom_only",
            "label": "Run custom YARA and Filescan",
            "description": "Run Filescan with custom signatures only (equivalent to --module Filescan --customonly).",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "download_yara_forge",
            "label": "Update YARA Forge rules",
            "description": "Download and replace the bundled YARA Forge rules with the latest release.",
            "type": "checkbox",
            "required": False,
        },
    ],
}

logger = get_task_logger(__name__)

CUSTOM_YARA_DIRS = [
    "/thor-lite/signatures/custom/yara",
    "/thor-lite/custom-signatures/yara",
]
CUSTOM_YARA_CLEAN_DIRS = [
    "/thor-lite/signatures/custom",
    "/thor-lite/custom-signatures",
] + CUSTOM_YARA_DIRS
YARA_FORGE_DIR = "/thor-lite/signatures/custom/yara-forge"
YARA_FORGE_PREFIX = "yara_forge_"


def _tail_last_line(path: str, max_bytes: int = 4096) -> str | None:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size <= 0:
                return None
            read_size = min(size, max_bytes)
            handle.seek(-read_size, os.SEEK_END)
            data = handle.read().decode(errors="replace")
    except FileNotFoundError:
        return None

    for line in reversed(data.splitlines()):
        line = line.strip()
        if line:
            return line
    return None


def _consume_log_updates(path: str, offset: int) -> tuple[int, int]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            data = handle.read()
            new_offset = handle.tell()
    except FileNotFoundError:
        return offset, 0

    if not data:
        return new_offset, 0

    added_hits = data.lower().count("yara rule")
    return new_offset, added_hits


def _safe_extract_zip(zip_file: zipfile.ZipFile, destination: str) -> None:
    destination = os.path.abspath(destination)
    for member in zip_file.namelist():
        member_path = os.path.abspath(os.path.join(destination, member))
        if not member_path.startswith(destination + os.sep) and member_path != destination:
            raise ValueError(f"Zip member would escape destination: {member}")
    zip_file.extractall(destination)


def _is_yara_file(filename: str) -> bool:
    return filename.lower().endswith((".yar", ".yara"))


def _flatten_yara_forge_rules() -> int:
    if not os.path.isdir(YARA_FORGE_DIR):
        return 0

    file_entries = []
    for root, _, files in os.walk(YARA_FORGE_DIR):
        for filename in files:
            if not _is_yara_file(filename):
                continue
            source_path = os.path.join(root, filename)
            rel_path = os.path.relpath(source_path, YARA_FORGE_DIR)
            digest = hashlib.sha1(rel_path.encode("utf-8")).hexdigest()[:12]
            dest_name = f"{YARA_FORGE_PREFIX}{digest}_{filename}"
            file_entries.append((source_path, dest_name))

    for custom_dir in CUSTOM_YARA_CLEAN_DIRS:
        os.makedirs(custom_dir, exist_ok=True)
        for name in os.listdir(custom_dir):
            if name.startswith(YARA_FORGE_PREFIX) and _is_yara_file(name):
                os.remove(os.path.join(custom_dir, name))

    for custom_dir in CUSTOM_YARA_DIRS:
        os.makedirs(custom_dir, exist_ok=True)
        for source_path, dest_name in file_entries:
            shutil.copy2(source_path, os.path.join(custom_dir, dest_name))

    return len(file_entries)


def _coerce_bool(value: str | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _first_value(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _get_signature_status() -> dict:
    signatures_dir = "/thor-lite/signatures"
    version_files = [
        "/thor-lite/signatures/version.txt",
        "/thor-lite/signatures/version",
        "/thor-lite/signatures/versions.txt",
        "/thor-lite/signatures/versions.json",
        "/thor-lite/signatures/siginfo.txt",
    ]

    version = None
    for path in version_files:
        if not os.path.exists(path):
            continue
        try:
            content = open(path, "r", encoding="utf-8").read().strip()
        except OSError:
            continue
        if not content:
            continue
        if path.endswith(".json"):
            try:
                payload = json.loads(content)
                version = (
                    payload.get("version")
                    or payload.get("signature_version")
                    or payload.get("signatures")
                )
            except json.JSONDecodeError:
                version = None
        else:
            version = content.splitlines()[0]
        if version:
            break

    updated_at = None
    if os.path.exists(signatures_dir):
        updated_at = datetime.fromtimestamp(
            os.path.getmtime(signatures_dir), tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {"version": version, "updated_at": updated_at}


def _format_signature_status(status: dict) -> str | None:
    parts = []
    updated_at = status.get("updated_at")
    version = status.get("version")
    if updated_at:
        parts.append(f"Updated: {updated_at}")
    if version:
        parts.append(f"Version: {version}")
    if not parts:
        return None
    return " | ".join(parts)


def _summarize_log_line(line: str | None, max_len: int = 120) -> str | None:
    if not line:
        return None
    summary = line.strip()
    if "MODULE:" in summary and "MESSAGE:" in summary:
        module_part = summary.split("MODULE:", 1)[1]
        module = module_part.split("MESSAGE:", 1)[0].strip()
        message = summary.split("MESSAGE:", 1)[1].strip()
        summary = f"{module}: {message}"
    if "FILE:" in summary:
        prefix, file_part = summary.split("FILE:", 1)
        file_path = file_part.strip().split()[0]
        basename = os.path.basename(file_path)
        if "SCANID:" in prefix:
            prefix = prefix.split("SCANID:", 1)[0]
        summary = f"{prefix.strip()} FILE: {basename}".strip()
    elif "SCANID:" in summary:
        summary = summary.split("SCANID:", 1)[0].strip()
    if len(summary) > max_len:
        summary = summary[: max_len - 3].rstrip() + "..."
    return summary


def _update_signatures(task, task_config: dict | None) -> None:
    raw_update = _first_value((task_config or {}).get("update_signatures"))
    if not _coerce_bool(raw_update, default=False):
        return

    util_path = "/thor-lite/thor-lite-util"
    if not os.path.exists(util_path):
        logger.warning("THOR Lite signature update skipped; %s not found.", util_path)
        task.send_event(
            "task-progress",
            data={"message": "Signature update skipped (thor-lite-util missing)."},
        )
        return

    task.send_event("task-progress", data={"message": "Updating THOR Lite signatures..."})
    result = subprocess.run(
        [util_path, "upgrade"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logger.warning(
            "THOR Lite signature update failed (code %s). STDERR: %s STDOUT: %s",
            result.returncode,
            (result.stderr or "").strip() or "<empty>",
            (result.stdout or "").strip() or "<empty>",
        )
        task.send_event(
            "task-progress",
            data={"message": "Signature update failed; continuing scan."},
        )
        return

    task.send_event("task-progress", data={"message": "Signature update complete."})


def _download_yara_forge(task, task_config: dict | None) -> None:
    raw_download = _first_value((task_config or {}).get("download_yara_forge"))
    if not _coerce_bool(raw_download, default=False):
        return

    url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
    dest_dir = YARA_FORGE_DIR
    parent_dir = os.path.dirname(dest_dir)
    os.makedirs(parent_dir, exist_ok=True)

    task.send_event("task-progress", data={"message": "Updating YARA Forge rules..."})
    with TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "yara-forge.zip")
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(
                zip_path, "wb"
            ) as handle:
                shutil.copyfileobj(response, handle)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Failed to download YARA Forge rules: {exc}") from exc

        extract_dir = os.path.join(temp_dir, "extract")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path) as archive:
                _safe_extract_zip(archive, extract_dir)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Failed to extract YARA Forge rules: {exc}") from exc

        if os.path.isdir(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.move(extract_dir, dest_dir)

    _flatten_yara_forge_rules()
    task.send_event("task-progress", data={"message": "YARA Forge rules updated."})


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def thor(  # pylint: disable=too-many-arguments
    self,
    pipe_result: str | None = None,
    input_files: list | None = None,
    output_path: str | None = None,
    workflow_id: str | None = None,
    task_config: dict | None = None,  # pylint: disable=unused-argument
) -> str:
    """Run Thor Lite on input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """
    # pylint: disable=too-many-locals
    logger.debug("Running Thor Lite task")
    input_files = get_input_files(pipe_result, input_files or []) or []
    output_files = []
    total_inputs = len(input_files)
    if total_inputs:
        self.send_event(
            "task-progress",
            data={"current": 0, "total": total_inputs, "message": "Preparing inputs"},
        )

    # Create output files
    html_output = create_output_file(
        output_path,
        display_name="Thor_Lite_HTML_report.html",
        data_type="openrelik:worker:thor-lite:html_report",
    )

    json_log = create_output_file(
        output_path,
        display_name="Thor_Lite_JSON_log.json",
        data_type="openrelik:worker:thor-lite:json_log",
    )

    txt_log = create_output_file(
        output_path,
        display_name="Thor_Lite_TXT_log.txt",
        data_type="openrelik:worker:thor-lite:txt_log",
    )

    json_v2_enabled = _coerce_bool(
        _first_value((task_config or {}).get("json_v2")),
        default=True,
    )
    custom_only = _coerce_bool(
        _first_value((task_config or {}).get("custom_only")),
        default=False,
    )

    # Thor Lite command
    command = [
        "/thor-lite/thor-lite-linux-64",
        "--intense",
        "--norescontrol",
        "--cross-platform",
        "--htmlfile",
        html_output.path,
        "--logfile",
        txt_log.path,
        "--jsonfile",
        json_log.path,
        "--rebase-dir",
        output_path,
    ]
    if custom_only:
        command.extend(["--module", "Filescan"])
        command.append("--customonly")
    if json_v2_enabled:
        command.append("--jsonv2")

    # Debugging information
    if not os.getenv("THOR_LITE_WORKER_DEBUG"):
        command.append("--silent")

    signature_status = _get_signature_status()
    signature_status_message = _format_signature_status(signature_status)
    if signature_status_message:
        self.send_event("task-progress", data={"message": signature_status_message})

    _update_signatures(self, task_config)
    _download_yara_forge(self, task_config)
    forge_count = _flatten_yara_forge_rules()
    custom_yara_loaded = forge_count
    if custom_yara_loaded:
        self.send_event(
            "task-progress",
            data={"message": f"Custom YARA rules loaded: {custom_yara_loaded}"},
        )

    signature_status = _get_signature_status()
    signature_status_message = _format_signature_status(signature_status)
    if signature_status_message:
        self.send_event("task-progress", data={"message": signature_status_message})

    # Prepare input files and run Thor Lite
    logger.debug("Creating temporary directory for Thor Lite processing.")
    with TemporaryDirectory(dir=output_path) as temp_dir:
        # Hard link input files for processing
        logger.debug("Preparing input files for Thor Lite processing (extract ZIPs, link others).")
        prepared_count = 0
        for idx, input_file in enumerate(input_files, start=1):
            path = input_file.get("path")
            if not path or not os.path.exists(path):
                raise RuntimeError(f"Input file missing or not found: {path}")

            filename = os.path.basename(path)
            self.send_event(
                "task-progress",
                data={
                    "current": idx,
                    "total": total_inputs,
                    "message": f"Preparing input {idx}/{total_inputs}: {filename}",
                },
            )
            if zipfile.is_zipfile(path):
                extract_dir_name = f"zip_{idx}_{os.path.splitext(filename)[0] or 'archive'}"
                extract_dir = os.path.join(temp_dir, extract_dir_name)
                logger.debug("Extracting ZIP input for Thor Lite", extra={"source": path, "destination": extract_dir})
                os.makedirs(extract_dir, exist_ok=True)
                with zipfile.ZipFile(path) as archive:
                    archive.extractall(extract_dir)
                prepared_count += sum(1 for _ in os.scandir(extract_dir))
            else:
                os.link(path, f"{temp_dir}/{filename}")
                prepared_count += 1

        # Sanity check
        if prepared_count == 0:
            raise RuntimeError("No input files prepared for THOR Lite scan (after extraction/linking).")

        self.send_event(
            "task-progress",
            data={"message": f"Prepared {prepared_count} items. Starting THOR Lite scan."},
        )

        # Add the created temporary directory to the command for processing.
        command.append("--path")
        command.append(temp_dir)

        # Run Thor Lite
        progress_update_interval_in_s: Final[int] = 2
        logger.debug("Running Thor")
        command_str = " ".join(command)
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as proc:
            logger.debug("Waiting for Thor to finish")
            scan_start = time.monotonic()
            log_offset = 0
            yara_hits = 0
            while proc.poll() is None:
                elapsed_s = int(time.monotonic() - scan_start)
                last_line = _tail_last_line(txt_log.path)
                log_offset, added_hits = _consume_log_updates(txt_log.path, log_offset)
                yara_hits += added_hits
                header = f"Status: THOR Lite scanning (elapsed {elapsed_s}s)"
                log_summary = _summarize_log_line(last_line)
                signature_line = (
                    f"Signatures: {signature_status_message}"
                    if signature_status_message
                    else None
                )
                custom_line = None
                if custom_only:
                    custom_line = (
                        "Custom YARA + Filescan: enabled "
                        f"(rules loaded: {custom_yara_loaded}, hits: {yara_hits})"
                    )
                log_line = f"Last log: {log_summary}" if log_summary else None
                message_lines = [signature_line, custom_line, header, log_line]
                message = "\n".join(line for line in message_lines if line)
                self.send_event(
                    "task-progress",
                    data={"message": message},
                )
                time.sleep(progress_update_interval_in_s)
            stdout, stderr = proc.communicate(timeout=1)
        returncode = proc.returncode
        stderr_msg = (stderr or "").strip()
        stdout_msg = (stdout or "").strip()

    # Populate the list of resulting output files.
    logger.debug("Collecting output files")
    for output_file in [html_output, json_log, txt_log]:
        if os.path.exists(output_file.path) and os.stat(output_file.path).st_size > 0:
            output_files.append(output_file.to_dict())

    if returncode != 0:
        if not output_files:
            raise RuntimeError(
                "THOR Lite failed with exit code "
                f"{returncode}. Command: {command_str}. "
                f"STDERR: {stderr_msg or '<empty>'}. "
                f"STDOUT: {stdout_msg or '<empty>'}"
            )
        logger.warning(
            "THOR Lite exited with code %s but produced outputs. STDERR: %s STDOUT: %s",
            returncode,
            stderr_msg or "<empty>",
            stdout_msg or "<empty>",
        )

    meta = {}
    signature_status = _get_signature_status()
    if signature_status.get("version"):
        meta["signature_version"] = signature_status["version"]
    if signature_status.get("updated_at"):
        meta["signature_updated_at"] = signature_status["updated_at"]
    if returncode != 0:
        meta["thor_exit_code"] = returncode
        if stderr_msg:
            meta["thor_stderr"] = stderr_msg[:2000]
        if stdout_msg:
            meta["thor_stdout"] = stdout_msg[:2000]

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=command_str,
        meta=meta,
    )
