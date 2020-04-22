""" Rule parser

"""
import json
import re
import tarfile
import tempfile
import uuid
from pathlib import Path

import magic
import yaml
from pathos.threading import ThreadPool

from . import log, run
from .report import Reporter


class RuleSpec:
    def __init__(self, stanza):
        self.stanza = stanza
        self.uuid = str(uuid.uuid4())

    @property
    def id(self):
        return f"{self.stanza['id']}-{self.uuid}"

    @property
    def name(self):
        return self.stanza["id"]

    @property
    def friendly_name(self):
        return self.stanza["id"].replace("-", " ")

    @property
    def description(self):
        return self.stanza["description"]

    @property
    def start_marker(self):
        return re.compile(self.stanza["start_marker"])

    @property
    def end_marker(self):
        return re.compile(self.stanza["end_marker"])

    def __str__(self):
        return f"<Rule: {self.id}>"


class RuleLoader:
    def __init__(self, rule_p):
        self.rules = yaml.safe_load(rule_p.read_text())

    def parse(self):
        """ Parses each rule into a RuleSpec
        """
        return [RuleSpec(rule) for rule in self.rules]


class RuleProcessor:
    def __init__(self, rule, file_p, output):
        self.rule = rule
        self.file_p = file_p
        self.output = output
        self.is_matching = False
        self.results = []
        self.result_map = {}

    def _process(self, line):
        if not self.is_matching and self.rule.start_marker.search(line):
            log.info(f"[match] START: {self.file_p}")
            self.is_matching = True
            self.results.append(line.strip())
        elif self.is_matching and self.rule.end_marker.search(line):
            self.is_matching = False
            self.results.append(line.strip())
            log.info(f"[match] END: {self.file_p}")
        elif self.is_matching:
            log.debug(f"[match] CAPTURE: {line.strip()}")
            self.results.append(line.strip())

    def analyze(self):
        with open(str(self.file_p)) as f:
            for line in f:
                self._process(line)

        if self.results:
            identifier = str(uuid.uuid4()).split("-")[0]
            outfile_json = self.output / f"{self.file_p.name}-{identifier}.json"
            outfile_txt = self.output / f"{self.file_p.name}-{identifier}-result.txt"
            # XXX: cleanup with structured class
            self.result_map = {
                "rule": self.rule.name,
                "name": self.rule.friendly_name,
                "filename": str(self.file_p),
                "results": "\n".join(self.results),
            }
            outfile_json.write_text(json.dumps(self.result_map))
            outfile_txt.write_text("\n".join(self.results))
            log.info(f"Capture stored at {outfile_json} and {outfile_txt}")

    @property
    def result(self):
        return self.result_map


class RuleWorker:
    def __init__(self, rules, output):
        self.rules = rules
        self.workdir = tempfile.mkdtemp()
        self.output = output
        self.files_to_process = []

    def extract(self, tarball):
        """ Extracts tarball into tmpdirectory
        """
        log.info(f"Extracting {tarball}")
        tar = tarfile.open(str(tarball), "r")
        for item in tar:
            log.debug(f"xx {item}")
            try:
                tar.extract(item, str(self.workdir))
                if (
                    item.name.find(".tar.gz") != -1
                    or item.name.find(".tar.xz") != -1
                    or item.name.find(".tgz") != -1
                ):
                    self.extract(f"{self.workdir}/{item.name}")
            except PermissionError as e:
                log.debug(f"xx unable to read {self.workdir}/{item.name}")
                continue

    def cleanup(self):
        log.info(f"Cleaning up {self.workdir}")
        run.cmd_ok(f"rm -rf {self.workdir}", shell=True)

    def build_file_list(self):
        """ Generates a list of searchable files to process
        """
        log.info(f"Generating files to process")
        _paths = Path(self.workdir).glob("**/*")
        for _path in _paths:
            if (
                not _path.is_dir()
                and magic.from_file(str(_path), mime=True) == "text/plain"
            ):
                for rule in self.rules:
                    log.debug(f":: adding process rule: {rule} to {_path}")
                    self.files_to_process.append(
                        RuleProcessor(rule, _path, self.output)
                    )

    def __process(self, rule_processor):
        rule_processor.analyze()

    def process(self):
        """ process rules
        """
        pool = ThreadPool()
        pool.map(self.__process, self.files_to_process)

    def report(self):
        results_list = [
            item.result_map for item in self.files_to_process if item.result_map
        ]
        report_p = self.output / "columbo-report.json"
        report_p.write_text(json.dumps(results_list))
        self.report_html()
        self.report_text()

    def report_html(self):
        log.info("Generating HTML Report")
        report_p = self.output / "columbo-report.html"
        r = Reporter()
        output = [r.header, "<h2>Columbo Report</h2><hr/>"]
        for item in self.files_to_process:
            if not item.result_map:
                continue

            output.append("<div class='row'>")
            output.append("<div class='col'>")
            output.append(f"<h3>{item.result_map['name']}</h3>")
            output.append(f"<p><strong>{item.result_map['filename']}</strong></p>")
            output.append(f"<pre>{item.result_map['results']}</pre>")
            output.append("</div>")
            output.append("</div>")
        output.append(r.footer)
        report_p.write_text("\n".join(output))

    def report_text(self):
        log.info("Generating TXT Report")
        report_p = self.output / "columbo-report.txt"
        r = Reporter()
        output = ["Columbo Report", "=" * 79]
        for item in self.files_to_process:
            if not item.result_map:
                continue
            output.append(item.result_map["name"])
            output.append(item.result_map["filename"])
            output.append(item.result_map["results"])
            output.append("-" * 79)
            output.append("")
        report_p.write_text("\n".join(output))
