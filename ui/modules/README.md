# Piannaple modules

Add one Python file per feature. It must expose:

```python
def register(manager):
    manager.add_widget(MyScreen(name="my-screen"))
```

The loader imports modules in filename order and skips a module that fails to
load, keeping the home screen available. Put tool-specific API calls and UI in
the module rather than adding more logic to `home_screen.py`.
