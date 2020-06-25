# columbo

columbo - got them clues

## Usage

```
> pip install columbo
> columbo --rules columbo.yaml --output-dir ~/tmp/output <tarball>
```

## Description

Pretty straightforward, it parses a yaml specification of regexs and tries to
find errors/concerns within output files. It'll take any tarball with plain text
files and parse each file concurrently for matches. All individual results are
stored in both json and text files for both machines and humans.

## Rules Spec

An example rules file looks like:

```yaml

- id: python-tb-exception
  description: parses logs for tracebacks
  start_marker: "^Traceback.*"
  end_marker: "^.*Error|InvalidRequest:"
```

You can also match by line:

```yaml

- id: subprocess-exit-status
  description: pulls lines with an exit status in the text
  line_match: "exit status 1"
```


## AsciiCast

[![asciicast](https://asciinema.org/a/MUs0GdCUxsN89C3fDlRUEHfKI.svg)](https://asciinema.org/a/MUs0GdCUxsN89C3fDlRUEHfKI)

## More information

- [Website / Documentation](https://columbo.8op.org)
