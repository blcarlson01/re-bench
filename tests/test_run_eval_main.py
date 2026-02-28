import pytest

from run_eval import main


def test_run_eval_main_raises_runtime_error():
    with pytest.raises(RuntimeError):
        main()
