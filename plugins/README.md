# pii-guardian Plugin System

Plugins are executables (any language) invoked as subprocesses. Communication
is JSON over stdin/stdout.

## Plugin Contract

**Input** (written to plugin stdin as one JSON object):

```json
{
  "action": "detect",
  "file": "/path/to/file",
  "segments": [
    { "id": "seg-1", "text": "John Smith called about account 4111111111111111", "key_context": null }
  ],
  "config": {}
}
```

**Output** (one JSON object on stdout):

```json
{
  "findings": [
    {
      "segment_id": "seg-1",
      "type": "name",
      "value": "John Smith",
      "confidence": 0.85,
      "start": 0,
      "end": 10
    }
  ]
}
```

Non-zero exit code = plugin failure; logged as warning, scan continues.

## Registering a Plugin

In your config file:

```jsonc
detectors: {
  name: {
    strategy: "plugin",
    plugin: "ner_spacy",   // matches filename in plugins/ without extension
  }
}
```

## Plugin Search Path

1. `plugins/` relative to the config file
2. `~/.config/pii-guardian/plugins/`
3. Directories in `$PATH`
