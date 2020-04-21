# columbo

columbo - got them clues

## Usage

```
> pip install columbo
> columbo --rules parser.yaml --output-dir ~/tmp/output <tarball>

```

## Description

Pretty straightforward, it parses a yaml specification of regexs and tries to
find errors/concerns within output files.

## Rules Spec

An example rules file looks like:

```yaml

- id: python-tb-exception
  description: parses logs for tracebacks
  start_marker: "^Traceback.*"
  end_marker: "^.*Error|InvalidRequest:"
```

## More information

- [Website / Documentation](https://columbo.8op.org)