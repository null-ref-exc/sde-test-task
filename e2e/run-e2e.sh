#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir="$script_dir/.."
docker_mode=false
skip_build=false

for argument in "$@"; do
    case "$argument" in
        --docker) docker_mode=true ;;
        --skip-build) skip_build=true ;;
        --help|-h)
            echo 'Usage: sh e2e/run-e2e.sh [--docker] [--skip-build]'
            exit 0 ;;
        *) echo "Unknown argument: $argument" >&2; exit 2 ;;
    esac
done

python_command=${PYTHON:-python3}
if ! command -v "$python_command" >/dev/null 2>&1; then
    echo 'Python 3.10+ is required. Set PYTHON to its executable if needed.' >&2
    exit 1
fi

"$python_command" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'

if [ "$skip_build" = false ]; then
    if [ "$docker_mode" = true ]; then
        docker build -t vulnerability-tracker:e2e "$project_dir"
    else
        (
            cd "$project_dir"
            dotnet tool restore
            dotnet build VulnerabilityTracker.slnx -c Release -v:q
        )
    fi
fi

if [ "$docker_mode" = true ]; then
    exec "$python_command" "$script_dir/e2e.py" --docker-image vulnerability-tracker:e2e
else
    exec "$python_command" "$script_dir/e2e.py"
fi
