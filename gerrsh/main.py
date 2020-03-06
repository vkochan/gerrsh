#!/usr/bin/env python

from __future__ import print_function

from subprocess import PIPE
import subprocess
import argparse
import json
import enum
import sys
import re
import os

def error(msg):
    print("ERROR: %s" % msg)

class GerrUser:
    def __init__(self, data=None):
        if data is None:
            self.username = ""
            self.fullname = ""
            self.email = ""
        else:
            self.username = data["username"]
            self.email = data["email"]
            if "name" in data:
                self.fullname = data["name"]
            else:
                self.fullname = self.username

    def __str__(self):
        return "%s <%s>" % (self.fullname, self.email)

class GerrApprovType(enum.Enum):
    Unknown = 0
    Verify = 1
    Review = 2

class GerrApprove:
    def __init__(self):
        self.user = None
        self.type = GerrApprovType.Unknown
        self.value = 0

class GerrFileStateType(enum.Enum):
    Unknown = -1,
    Added = 0,
    Modified = 1,
    Deleted = 2,
    Renamed = 3,

class GerrFile:
    def __init__(self):
        self.path = ""
        self.dels = 0
        self.ins = 0

class GerrPatchSet:
    def __init__(self):
        self.approvals = []
        self.files = []
        self.verify = None
        self.review = None
        self.author = None
        self.uploader = None
        self.revision = ""
        self.git_ref = ""
        self.num = -1

class GerrChange:
    def __init__(self):
        self.id = ""
        self.branch = ""
        self.topic = ""
        self.num = -1
        self.subject = ""
        self.owner = None
        self.reviewers = []
        self.commit_msg = ""
        self.created_on = None
        self.updated_on = None
        self.wip = False
        self.project = ""
        self.curr_patchset = None

class Gerrsh:
    def __init__(self, url, port=29418):
        self.port = port
        self.url = url
        self.cmd = ["ssh", "-p", str(port), url, "gerrit"]
        self.changes = []

    def do_cmd(self, name, args=[]):
        cmd = [name] + args
        return subprocess.check_output(self.cmd + cmd).decode("utf-8")
        # proc = subprocess.run(self.cmd + cmd, stdout=PIPE)
        # proc.check_returncode()
        # return proc.stdout.decode("utf-8")

    def __query_changes(self, filter_list=[]):
        params = ["--format=json", "--files", "--comments", "--all-reviewers", "--current-patch-set", "status:open"]
        params.append(" ".join(filter_list))
        changes = []
        resp = self.do_cmd("query", params)
        for line in resp.split("\n"):
            if len(line) > 0 and line[0] == "{":
                data = json.loads(line)
                if "type" not in data:
                    changes.append(data)
        return changes

    def __parse_reviewers(self, ch, data):
        if "allReviewers" in data:
            for r in data["allReviewers"]:
                ch.reviewers.append(GerrUser(r))

    def __parse_patchset_approvals(self, ps, data):
        verify = GerrApprove()
        verify.type = GerrApprovType.Verify
        verify.value = 0

        review = GerrApprove()
        review.type = GerrApprovType.Review
        review.value = 0

        if "approvals" in data:
            for a in data["approvals"]:
                appr = GerrApprove()
                appr.value = int(a["value"])
                appr.user = GerrUser(a["by"])
                if a["type"] == "Code-Review":
                    if review is None:
                        review = appr
                    elif appr.value != 0:
                        review = appr if appr.value < 0 and appr.value < review.value else review
                        review = appr if review.value >= 0 and appr.value > review.value else review
                    appr.type = GerrApprovType.Review
                elif a["type"] == "Verified":
                    if verify is None:
                        verify = appr
                    elif appr.value != 0:
                        verify = appr if appr.value < 0 and appr.value < verify.value else verify
                        verify = appr if verify.value >= 0 and appr.value > verify.value else verify
                    appr.type = GerrApprovType.Verify

                ps.approvals.append(appr)

        ps.verify = verify
        ps.review = review

    def __parse_patchset_files(self, ps, data):
        if "files" in data:
            for f in data["files"]:
                if f["file"] != "/COMMIT_MSG":
                    file = GerrFile()
                    file.dels = int(f["deletions"])
                    file.ins = int(f["insertions"])
                    file.path = f["file"]

                    if f["type"] == "ADDED":
                        file.type = GerrFileStateType.Added
                    elif f["type"] == "MODIFIED":
                        file.type = GerrFileStateType.Modified
                    elif f["type"] == "DELETED":
                        file.type = GerrFileStateType.Deleted
                    elif f["type"] == "RENAMED":
                        file.type = GerrFileStateType.Renamed
                    else:
                        file.type = GerrFileStateType.Unknown

                    ps.files.append(file)

    def __parse_patchset(self, data):
        ps = GerrPatchSet()

        ps.git_ref = data["ref"] if "ref" in data else ""

        ps.author = GerrUser()
        ps.author.username = data["author"]["username"]
        ps.author.fullname = data["author"]["name"]
        ps.author.email = data["author"]["email"]

        ps.uploader = GerrUser()
        ps.uploader.username = data["uploader"]["username"]
        ps.uploader.fullname = data["uploader"]["name"]
        ps.uploader.email = data["uploader"]["email"]

        self.__parse_patchset_approvals(ps, data)
        self.__parse_patchset_files(ps, data)

        return ps

    def get_changes(self, filter_list=[]):
        changes = self.__query_changes(filter_list)

        for c in changes:
            ch = GerrChange()
            ch.id = c["id"]
            ch.num = c["number"]
            ch.branch = c["branch"]
            ch.subject = c["subject"]
            ch.project = c["project"]
            ch.commit_msg = c["commitMessage"]

            if "topic" in c:
                ch.topic = c["topic"]

            ch.owner = GerrUser()
            ch.owner.username = c["owner"]["username"]
            ch.owner.fullname = c["owner"]["name"]
            ch.owner.email = c["owner"]["email"]

            ch.curr_patchset = self.__parse_patchset(c["currentPatchSet"])

            self.__parse_reviewers(ch, c)

            self.changes.append(ch)

        return self.changes

    def add_comment(self):
        pass

def review_state_fmt(name, value):
    if value == 0:
        return "-"
    sign = ""
    if value > 0:
        sign = "+"
    return "%s%s%s" % (name, sign, value)

def approv_fmt(appr):
    sign = ""
    if appr.value > 0:
        sign = "+"
    return "%s (%s%d)" % (str(appr.user), sign, appr.value)

def list_changes(changes):
    for c in changes:
        verify = review_state_fmt("V", c.curr_patchset.verify.value)
        review = review_state_fmt("CR", c.curr_patchset.review.value)
        state = verify + " " + review

        print("%-8s%-10s%-20s%-20s%-25s%s" % (c.num, state, c.project, c.branch, c.owner.username, c.subject))

def show_change(ch):
    ps = ch.curr_patchset

    print(ch.commit_msg)
    print("Owner: %s" % str(ch.owner))
    print("Author: %s" % str(ps.author))
    print("Uploader: %s" % str(ps.uploader))

    print("")

    rewr_list = [str(r) for r in ch.reviewers]
    print("Reviewers:", end="")
    if len(rewr_list) >= 1:
        print(" %s" % rewr_list[0])
        for r in ch.reviewers[1:]:
            print("           %s" % str(r))

    print("")

    print("Project: %s" % ch.project)
    print("Branch: %s" % ch.branch)
    print("Topic: %s" % ch.topic)
    print("Ref: %s" % ps.git_ref)

    print("")

    rev_list = [a for a in ps.approvals if a.type == GerrApprovType.Review]
    print("Code-review:", end="")
    if len(rev_list) >= 1:
        print(" %s" % approv_fmt(rev_list[0]))
        for rev in rev_list[1:]:
            print("        %s" % approv_fmt(rev))
    else:
        print("")

    verify_list = [a for a in ps.approvals if a.type == GerrApprovType.Verify]
    print("Verify:", end="")
    if len(verify_list) >= 1:
        print(" %s" % approv_fmt(verify_list[0]))
        for v in verify_list[1:]:
            print("        %s" % approv_fmt(v))
    else:
        print("")

    print("")

    print("Stats:")
    dels = 0
    ins = 0

    for f in ps.files:
        state = " " 
        if f.type == GerrFileStateType.Added:
            state = "A"
        elif f.type == GerrFileStateType.Modified:
            state = "M"
        elif f.type == GerrFileStateType.Deleted:
            state = "D"
        elif f.type == GerrFileStateType.Renamed:
            state = "R"

        stats = "+%d/-%d" % (f.ins, -f.dels)
        dels = dels + f.dels
        ins = ins + f.ins
        print("    %s %-10s %s" % (state, stats, f.path))

    print("      %s" % ("+%d/-%d" % (ins, -dels)))

def get_change_branch(ch):
    topic = ch.topic if ch.topic != "" else ch.num
    author = re.sub(r'\W+', '_', ch.owner.fullname).lower()
    return "review/%s/%s" % (author, topic)

def get_change(ch):
    ref = ch.curr_patchset.git_ref
    cmd = ["git", "fetch", "origin", ref]

    try:
        subprocess.check_call(cmd)
    except:
        error("failed to fetch change %s from remote %s" % (ch.num, ref))
        sys.exit(1)

    branch = get_change_branch(ch)

    try:
        cmd = ["git", "checkout", "-b", branch, "FETCH_HEAD"]
        subprocess.check_call(cmd)
    except:
        error("failed to checkout change %s to branch %s" % (ch.num, branch))
        sys.exit(1)

def checkout_change(ch):
    branch = get_change_branch(ch)
    cmd = ["git", "checkout", branch]

    try:
        subprocess.check_call(cmd)
    except:
        error("failed to checkout change %s to branch %s" % (ch.num, branch))
        sys.exit(1)

def main():
    usage = "gerrsh [OPTIONS] ... [CHANGEID]"
    description = """
Tool for review changes from Gerrit

By default all open changes are listed.
"""

    parser = argparse.ArgumentParser(usage=usage, description=description)
    parser.add_argument("--my", dest="my", action="store_true",
                        help="select only my changes")
    parser.add_argument("-M", "--no-conflict", dest="no_conflict", action="store_true",
                        help="select changes without conflicts")
    parser.add_argument("-A", "--author", dest="author",
                        help="select changes of specified author")
    parser.add_argument("-O", "--owner", dest="owner",
                        help="select changes of specified owner")
    parser.add_argument("-g", "--get", dest="get", action="store_true",
                        help="fetch change from gerrit to git")
    parser.add_argument("-c", "--checkout", dest="checkout", action="store_true",
                        help="checkout already fetched change from gerrit")
    parser.add_argument("--host", dest="host",
                        help="gerrit host to fetch changes from")

    parser.add_argument("changeid", nargs="?")

    options = parser.parse_args()

    if options.host:
        host = options.host
    elif "GERRIT" in os.environ:
        host = os.environ["GERRIT"]
    else:
        error("please specify gerrit host")
        sys.exit(1)

    gersh = Gerrsh("gerrit.x.ow.s")

    filter_dict = {"status":"open"}
    filter_list = []

    if options.changeid:
        filter_dict["change"] = options.changeid
    if options.my:
        filter_dict["owner"] = "self"
    if options.no_conflict:
        filter_dict["is"] = "mergeable"
    if options.author:
        filter_dict["author"] = options.author
    if options.owner:
        filter_dict["owner"] = options.owner

    for k,v in filter_dict.items():
        filter_list.append("%s:%s" % (k, v))

    if options.changeid:
        changes = gersh.get_changes(filter_list)
        if len(changes) == 1:
            ch = changes[0]
            if options.get:
                get_change(ch)
            if options.checkout:
                checkout_change(ch)
            if not options.get and not options.checkout:
                show_change(ch)
        else:
            error("change not found")
            sys.exit(1)
    else:
        list_changes(gersh.get_changes(filter_list))

if __name__ == "__main__":
    main()
