from __future__ import annotations

from pathlib import Path
import shutil


def on_post_build(config, **kwargs):
    root = Path(config.config_file_path).parent
    source = root / "scripts" / "install.sh"
    destination = Path(config["site_dir"]) / "install.sh"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)