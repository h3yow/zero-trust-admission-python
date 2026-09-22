"""冒烟测试：应用可导入、默认策略可加载。"""


def test_app_imports() -> None:
    import main

    assert main.app.title == "zero-trust-admission-python"
    assert main.app.state.store.require().version >= 1
