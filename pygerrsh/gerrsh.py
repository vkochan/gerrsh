#!/usr/bin/env python

from __future__ import print_function

from tempfile import SpooledTemporaryFile as tempfile
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

class GerrComment:
    def __init__(self):
        self.file = None
        self.line = -1
        self.reviewer = None
        self.message = ""
        self.in_reply_to = -1

class GerrPatchSet:
    def __init__(self):
        self.approvals = []
        self.comments = []
        self.comments_by_line = {}
        self.comments_by_file = {}
        self.files = []
        self.verify = None
        self.review = None
        self.author = None
        self.uploader = None
        self.revision = ""
        self.git_ref = ""
        self.num = ""

class GerrChange:
    def __init__(self):
        self.id = ""
        self.branch = ""
        self.topic = ""
        self.num = ""
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

    def __parse_comments(self, ps, data):
        if "comments" in data:
            comments = []

            for c in data["comments"]:
                cm = GerrComment()
                cm.file = c["file"]
                cm.line = int(c["line"])
                cm.reviewer = GerrUser(c["reviewer"])
                cm.message = c["message"]

                comments.append(cm)

            ps.comments = sorted(comments, key=lambda comment: comment.line)
            for c in ps.comments:
                if c.line not in ps.comments_by_line:
                    ps.comments_by_line[c.line] = []
                ps.comments_by_line[c.line].append(c)

                if c.file not in ps.comments_by_file:
                    ps.comments_by_file[c.file] = []
                if c.line not in ps.comments_by_file[c.file]:
                    ps.comments_by_file[c.file].append(c.line)

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
        ps.num = data["number"]

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
        self.__parse_comments(ps, data)

        return ps

    def get_changes(self, filter_list=[]):
        chk_has_comments = "has:comments" in filter_list
        if chk_has_comments:
            filter_list.remove("has:comments")

        changes = self.__query_changes(filter_list)

        for c in changes:
            if chk_has_comments and "comments" not in c["currentPatchSet"]:
                continue
            ch = GerrChange()
            ch.id = c["id"]
            ch.num = c["number"]
            ch.branch = c["branch"]
            ch.subject = c["subject"]
            ch.project = c["project"]
            ch.wip = True if "wip" in c else False
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

    def review_change(self, ch, score, label=None, msg=None, comments=[], verify=False):
        data = {}
        if label or msg or len(comments) > 0:
            if label:
                data["labels"] = {label: score}
            if msg:
                data["message"] = msg
            if len(comments) > 0:
                data["comments"] = {}
                for c in comments:
                    if c.file not in data["comments"]:
                        data["comments"][c.file] = []

                    cdata = {}
                    cdata["message"] = c.message
                    cdata["unresolved"] = True
                    cdata["line"] = c.line
                    if c.in_reply_to >= 0:
                        cdata["in_reply_to"] = c.in_reply_to

                    data["comments"][c.file].append(cdata)
        else:
            return

        jdata = json.dumps(data).encode()

        if verify:
            print(jdata)
            return

        f = tempfile()
        f.write(jdata)
        f.seek(0)

        cmd = ["review", "--json", "%s,%s" % (ch.num, ch.curr_patchset.num)]
        try:
            subprocess.check_call(self.cmd + cmd, stdin=f)
        except:
            error("failed to submit review for change %s" % ch.num)
            f.close()
            sys.exit(1)

        f.close()

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
        wip = "W" if c.wip else " "

        state = "%s %-4s %-5s" % (wip, verify, review)

        print("%-8s%-14s%-20s%-20s%-25s%s" % (c.num, state, c.project, c.branch, c.owner.username, c.subject))

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

    if len(ps.comments) > 0:
        print("")
        for c in ps.comments:
            print("%s says on: %s +%d" % (c.reviewer.fullname, c.file, c.line))
            for s in c.message.splitlines():
                print("    %s" % s)
            print("")

def get_change_branch(ch):
    topic = ch.topic if ch.topic != "" else ch.num
    author = re.sub(r'\W+', '_', ch.owner.fullname).lower()
    return "review/%s/%s" % (author, topic)

def branch_exist(branch):
    cmd = ["git", "branch"]
    out = ""

    try:
        out = subprocess.check_output(cmd).decode("utf-8")
    except:
        error("failed to execute %s" % " ".join(cmd))
        sys.exit(1)

    return branch in [s.strip().replace("* ", "") for s in out.splitlines()]

def checkout_change(ch):
    ref = ch.curr_patchset.git_ref
    cmd = ["git", "fetch", "origin", ref]
    is_exist = False

    try:
        subprocess.check_call(cmd)
    except:
        error("failed to fetch change %s from remote %s" % (ch.num, ref))
        sys.exit(1)

    branch = get_change_branch(ch)
    is_exist = branch_exist(branch)
    cmd = ["git", "checkout"]

    if not is_exist:
        cmd.append("-b")

    cmd.append(branch)

    if not is_exist:
        cmd.append("FETCH_HEAD")

    try:
        subprocess.check_call(cmd)
    except:
        error("failed to checkout change %s to branch %s" % (ch.num, branch))
        sys.exit(1)

def comments_diff(ch):
    ps = ch.curr_patchset
    diff = []

    for f,lines in ps.comments_by_file.items():
        diff.append("--- a/%s" % f)
        diff.append("+++ b/%s" % f)
        lines_added = 0
        for l in lines:
            comments = ps.comments_by_line[l]
            comments_added = 0

            for c in comments:
                msg_list = c.message.splitlines()
                msg_lines = len(msg_list) + 1
                line = c.line + 1
                diff.append("@@ -%s,0 +%s,%s @@" % (line - 1, line + lines_added, msg_lines))
                prefix = ">" * (len(comments) - comments_added)
                diff.append("+%s %s wrote:" % (prefix, c.reviewer))
                for m in msg_list:
                    diff.append("+%s | %s" % (prefix, m))
                lines_added += msg_lines + 2
                comments_added += 1

    return os.linesep.join(diff) + os.linesep

def comments_apply(ch):
    f = tempfile()
    f.write(comments_diff(ch).encode())
    f.seek(0)

    try:
        subprocess.check_output(["patch", "-u", "--verbose", "-p1"], stdin=f)
    except:
        error("failed to apply comments from change %s" % ch.num)
        f.close()
        sys.exit(1)

    f.close()

def thread_comment_extract(ch, comments, i):
    pass

def new_comments_parse(ch):
    try:
        diff = subprocess.check_output(["git", "diff", "-U0"]).decode("utf-8")
    except:
        error("failed to get comments diff")
        sys.exit(1)

    hunk_pattern = "@@ -(?P<orig_idx>([0-9])*),(([0-9])*) \+(?P<new_idx>([0-9])*)(,(?P<new_num>([0-9])*))? @@.*"
    hunk_re = re.compile(hunk_pattern)
    path_orig_re = re.compile("--- ([^W]*)")
    path_new_re = re.compile("\+\+\+ ([^W]*)")
    diff_git_re = re.compile("diff --git .*")
    thread_re = re.compile("(?P<level>>+) .*")
    m_git_diff = None
    path = None

    diff_lines = diff.splitlines()
    ps = ch.curr_patchset
    comments = []
    i = 0
    while i < len(diff_lines):
        if not m_git_diff:
            m_git_diff = diff_git_re.search(diff_lines[i])
            if m_git_diff:
                i += 1
                continue

        m_path_orig = path_orig_re.search(diff_lines[i])
        if m_path_orig:
            m_path_new = path_new_re.search(diff_lines[i + 1])
            if m_path_orig and m_path_new:
                if m_git_diff:
                    path = re.sub("([^W]/)?", "", m_path_orig.group(1), 1)
                else:
                    path = m_path_orig.group(1)
                # skip '--- +++ path'
                i += 2
        m_hunk = hunk_re.match(diff_lines[i])
        if not m_hunk:
            i += 1
            continue
        i += 1

        if m_hunk.group("new_num"):
            line_count = int(m_hunk.group("new_num"))
        else:
            line_count = 1

        line_idx = int(m_hunk.group("orig_idx"))

        has_thread = False
        new_lines = []
        curr_thread = 0
        next_thread = 0
        j = 0

        # process the diff hunk
        while j < line_count:
            # skip diff's '+'
            line = diff_lines[i + j][1:]
            m_thread = thread_re.match(line)
            if m_thread:
                curr_thread = len(m_thread.group("level"))
                next_thread = curr_thread - 1
            else:
                new_lines.append(line)
            if len(new_lines) == 0:
                j += 1
                continue
            # if last line of hunk or thread changed
            if j == line_count - 1 or curr_thread != next_thread:
                reply_to = -1

                # NOTE: currently query command does not put comment id
                # in comment attributes, so it is impossible to
                # support in_reply_to feature.
                # if curr_thread > 0:
                #     thread_list = ps.comments_by_line[line_idx]
                #     reply_to = ps.comments.index(thread_list[len(thread_list) - curr_thread])

                c = GerrComment()
                c.line = line_idx
                c.file = path
                c.message = os.linesep.join(new_lines)
                c.in_reply_to = reply_to
                comments.append(c)

                next_thread = curr_thread
                new_lines[:] = []
            j += 1
        i += j
    return comments

def main():
    usage = "gerrsh [OPTIONS] ... [CHANGEID]"
    description = """
Tool for review changes from Gerrit

By default all open changes are listed.
"""

    fmt_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=60)
    parser = argparse.ArgumentParser(usage=usage, description=description, formatter_class=fmt_class)
    parser.add_argument("--my", dest="my", action="store_true",
                        help="select only my changes")
    parser.add_argument("-M", "--no-conflict", dest="no_conflict", action="store_true",
                        help="select changes without conflicts")
    parser.add_argument("-C", "--has-comments", dest="has_comments", action="store_true",
                        help="select changes which has comments")
    parser.add_argument("-A", "--author", dest="author",
                        help="select changes of specified author")
    parser.add_argument("-O", "--owner", dest="owner",
                        help="select changes of specified owner")
    parser.add_argument("-c", "--checkout", dest="checkout", action="store_true",
                        help="checkout change from gerrit")
    parser.add_argument("--comments-diff", dest="comments_diff", action="store_true",
                        help="show comments in the diff form")
    parser.add_argument("--comments-apply", dest="comments_apply", action="store_true",
                        help="apply comments as diff")
    parser.add_argument("--comments-push", dest="comments_push", action="store_true",
                        help="parse and push comments from local git diff")
    parser.add_argument("--review-score", dest="review_score",
                        help="specify review score (+1, etc)")
    parser.add_argument("--review-msg", dest="review_msg",
                        help="specify review message")
    parser.add_argument("--verify", dest="verify", action="store_true",
                        help="only verify JSON data output")
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

    gersh = Gerrsh(host)

    filter_dict = {"status":"open"}
    filter_list = []

    if options.changeid:
        filter_dict["change"] = options.changeid
    if options.my:
        filter_dict["owner"] = "self"
    if options.no_conflict:
        filter_list.append("is:mergeable")
    if options.has_comments:
        filter_list.append("has:comments")
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

            if options.checkout:
                checkout_change(ch)
                return
            if options.comments_diff:
                print(comments_diff(ch))
                return
            if options.comments_apply:
                comments_apply(ch)
                return
            if options.comments_push:
                new_comments = new_comments_parse(ch)
                if len(new_comments) == 0:
                    print("no new comments")
                    sys.exit(0)
                gersh.review_change(ch, None, None, None, new_comments, verify=options.verify)
                return
            if options.review_score or options.review_msg:
                gersh.review_change(ch, options.review_score, "Code-Review", options.review_msg, [], verify=options.verify)
                return

            show_change(ch)
        else:
            error("change not found")
            sys.exit(1)
    else:
        list_changes(gersh.get_changes(filter_list))

if __name__ == "__main__":
    main()
