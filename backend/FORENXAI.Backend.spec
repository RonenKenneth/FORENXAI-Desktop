# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import (
    collect_all,
    collect_submodules,
)

import os


# ============================================================
# PROJECT PATHS
# ============================================================

project_root = os.path.abspath(
    os.path.dirname(SPEC)
)

model_directory = os.path.join(
    project_root,
    "models",
    "forenxai"
)


# ============================================================
# DATA FILES
# ============================================================

datas = [
    (
        model_directory,
        os.path.join(
            "models",
            "forenxai"
        )
    ),
    # rules.json: every Tier 1 / Tier 2 threshold and the decision table.
    # rule_service resolves it relative to its own module, so it must sit
    # at app/rules inside the bundle.
    (
        os.path.join(
            project_root,
            "app",
            "rules"
        ),
        os.path.join(
            "app",
            "rules"
        )
    ),
]


# ============================================================
# HIDDEN IMPORTS
# ============================================================

hiddenimports = []


# Uvicorn loads several components dynamically.
hiddenimports += collect_submodules(
    "uvicorn"
)


# Make sure the FORENXAI application package is collected.
hiddenimports += collect_submodules(
    "app"
)


# scapy loads its protocol layers by name at runtime (packet parsing,
# Tier 2 packet rules), which static analysis cannot see.
hiddenimports += collect_submodules(
    "scapy"
)


# rag/config/*.py is loaded from disk with importlib (recommendation
# service), so its imports are invisible to PyInstaller. It reads the
# source PDFs through pypdf.
hiddenimports += collect_submodules(
    "pypdf"
)

# NOT bundled, shipped beside FORENXAI.Backend.exe instead (see SETUP.md):
#   models/llm/qwen2.5-3b-q4.gguf   ~2 GB, too large for a onefile .exe
#   rag/                            knowledge, config, index, sources
#   tools/                          Suricata, JDK 8, CICFlowMeter, Maven,
#                                   resolved by runtime_paths.find_tool


# ============================================================
# MACHINE LEARNING PACKAGES
# ============================================================

xgboost_datas, xgboost_binaries, xgboost_hiddenimports = (
    collect_all(
        "xgboost"
    )
)

shap_datas, shap_binaries, shap_hiddenimports = (
    collect_all(
        "shap"
    )
)

sklearn_datas, sklearn_binaries, sklearn_hiddenimports = (
    collect_all(
        "sklearn"
    )
)

numpy_datas, numpy_binaries, numpy_hiddenimports = (
    collect_all(
        "numpy"
    )
)

pandas_datas, pandas_binaries, pandas_hiddenimports = (
    collect_all(
        "pandas"
    )
)


# ============================================================
# LLAMA.CPP / QWEN RUNTIME
# ============================================================

llama_cpp_datas, llama_cpp_binaries, llama_cpp_hiddenimports = (
    collect_all(
        "llama_cpp"
    )
)


# ============================================================
# ADD PACKAGE DATA
# ============================================================

datas += xgboost_datas
datas += shap_datas
datas += sklearn_datas
datas += numpy_datas
datas += pandas_datas

datas += llama_cpp_datas


# ============================================================
# ADD PACKAGE BINARIES
# ============================================================

binaries = []

binaries += xgboost_binaries
binaries += shap_binaries
binaries += sklearn_binaries
binaries += numpy_binaries
binaries += pandas_binaries

binaries += llama_cpp_binaries


# ============================================================
# ADD PACKAGE HIDDEN IMPORTS
# ============================================================

hiddenimports += xgboost_hiddenimports
hiddenimports += shap_hiddenimports
hiddenimports += sklearn_hiddenimports
hiddenimports += numpy_hiddenimports
hiddenimports += pandas_hiddenimports

hiddenimports += llama_cpp_hiddenimports


# ============================================================
# ANALYSIS
# ============================================================

a = Analysis(
    ["run_backend.py"],

    pathex=[
        project_root
    ],

    binaries=binaries,

    datas=datas,

    hiddenimports=hiddenimports,

    hookspath=[],

    hooksconfig={},

    runtime_hooks=[],

    excludes=[],

    noarchive=False,

    optimize=0,
)


# ============================================================
# PYTHON ARCHIVE
# ============================================================

pyz = PYZ(
    a.pure
)


# ============================================================
# EXECUTABLE
# ============================================================

exe = EXE(
    pyz,

    a.scripts,

    a.binaries,

    a.datas,

    [],

    name="FORENXAI.Backend",

    debug=False,

    bootloader_ignore_signals=False,

    strip=False,

    upx=False,

    upx_exclude=[],

    runtime_tmpdir=None,

    console=True,

    disable_windowed_traceback=False,

    argv_emulation=False,

    target_arch=None,

    codesign_identity=None,

    entitlements_file=None,
)