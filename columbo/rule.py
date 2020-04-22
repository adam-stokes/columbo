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


class RuleSpec:
    def __init__(self, stanza):
        self.stanza = stanza
        self.uuid = str(uuid.uuid4())

    @property
    def id(self):
        return f"{self.stanza['id']}-{self.uuid}"

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

    def _process(self, line):
        if not self.is_matching and self.rule.start_marker.search(line):
            log.info(f"[match] START: {self.file_p}")
            self.is_matching = True
            self.results.append(line)
        elif self.is_matching and self.rule.end_marker.search(line):
            self.is_matching = False
            self.results.append(line)
            log.info(f"[match] END: {self.file_p}")
        elif self.is_matching:
            log.info(f"[match] CAPTURE: {line.strip()}")
            self.results.append(line)

    def analyze(self):
        with open(str(self.file_p)) as f:
            for line in f:
                self._process(line)

        if self.results:
            identifier = str(uuid.uuid4()).split("-")[0]
            outfile_json = self.output / f"{self.file_p.name}-{identifier}.json"
            outfile_txt = self.output / f"{self.file_p.name}-{identifier}-result.txt"
            # XXX: cleanup with structured class
            file_map = {
                "filename": str(self.file_p),
                "results": "\n".join(self.results),
            }
            outfile_json.write_text(json.dumps(file_map))
            outfile_txt.write_text("\n".join(self.results))
            log.info(f"Capture stored at {outfile_json} and {outfile_txt}")


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
                    log.info(f":: adding process rule: {rule} to {_path}")
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

    @property
    def process_count(self):
        return len(self.files_to_process)
