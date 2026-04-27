import os
from pathlib import Path
import shutil

from invoke import task


@task
def venv(c):
    if not os.path.exists("venv"):
        c.run("python -m venv venv")
        print("venv created.")
    else:
        print("venv already exists.")

@task
def install(c, dev=False):
    """Install dependencies with Flit."""
    pip = "venv/bin/pip"
    c.run(f"{pip} install flit")
    if dev:
        c.run("venv/bin/flit install --symlink --deps develop")
    else:
        c.run("venv/bin/flit install --deps production")
        

@task
def test(c):
    """Run pytest with coverage"""
    c.run("coverage run -m pytest", pty=True)


@task
def coverage(c):
    """
    Runs the coverage report using the coverage tool.
    """
    c.run("coverage report", pty=True)


@task
def htmlcov(c):
    """
    Generates an HTML coverage report using the 'coverage' tool in html 
    format.
    """
    c.run("coverage html", pty=True)
    print("Open htmlcov/index.html in your browser")


@task
def lint(c):
    """Run flake8 linting"""
    c.run("flake8 keycard tests", pty=True)


@task
def typecheck(c):
    """Run mypy type checking."""
    c.run("mypy keycard")


@task
def docs(ctx, clean=False, open=False):
    """
    Build Sphinx documentation.

    Args:
        clean (bool): If True, removes the build directory before building.
        open (bool): If True, opens the built docs in a browser.
    """
    docs_dir = "docs"
    build_dir = os.path.join(docs_dir, "_build")

    if clean and os.path.exists(build_dir):
        ctx.run(f"rm -rf {build_dir}")

    ctx.run(f"sphinx-build -b html {docs_dir} {build_dir}/html")

    if open:
        index_path = os.path.join(build_dir, "html", "index.html")
        ctx.run(f"xdg-open {index_path} || open {index_path}", warn=True)


@task
def clean(c):
    """Clean artifacts"""
    for pycache in Path(".").rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)
        
    build_path = Path("docs") / "_build"
    if build_path.exists():
        shutil.rmtree(build_path, ignore_errors=True)
    
    c.run("rm -rf .pytest_cache htmlcov .coverage", warn=True)


@task
def cleanall(c):
    """Thorough cleanup of all build, cache, and pycache files."""
    patterns = [
        "__pycache__",
        ".pytest_cache",
        ".coverage",
        "htmlcov",
        "dist",
        "build",
        "*.egg-info",
        "venv"
    ]

    for pattern in patterns:
        for path in Path(".").rglob(pattern):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                path.unlink(missing_ok=True)

    # Sphinx docs
    docs_build = Path("docs") / "_build"
    if docs_build.exists():
        shutil.rmtree(docs_build, ignore_errors=True)
    print("All artifacts cleaned up.")
