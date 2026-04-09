import os
import sys
from pathlib import Path

def test_python_version():
    assert sys.version_info >= (3, 12), "Ошибка: нужен Python 3.12+"

def test_internal_storage():
    base = Path(__file__).resolve().parent.parent.parent
    for folder in ["sqlite", "qdrant", "viking"]:
        p = base / "storage" / folder
        assert p.exists(), f"Папка {p} не найдена"

def test_external_models():
    # Проверка /srv/dev-team/models_data относительно этого файла
    models = Path(__file__).resolve().parent.parent.parent.parent / "models_data"
    assert models.exists(), f"Внешняя папка {models} не найдена"
    assert os.access(models, os.R_OK), "Нет прав на чтение models_data"
