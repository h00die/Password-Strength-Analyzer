#!/us/bin/python3

'''
Date: Jan 16, 2016
Author: h00die
Description: This program takes JtR output or a wordlist and does a password analysis on it to determine the password length statistics and complexity.
            In order to give the correct JtR output you must run: john --show <hashes_file> > jtroutput
'''
import argparse
import re
import sys
import os.path
import locale
from collections import Counter
import numpy
try:
    from progressbar import ProgressBar
except ImportError:
    #http://progressbar-2.readthedocs.org/en/latest/usage.html#wrapping-an-iterable
    quit("progressbar missing.  pip install progressbar2")

def is_valid_file(parser, arg):
    '''Ensure we're passed a valid file'''
    if not os.path.isfile(arg):
        parser.error("The file %s does not exist!" %(arg))
    else:
        return arg

locale.setlocale(locale.LC_ALL, 'en_US')

parser = argparse.ArgumentParser(description='''
This program takes a password list and performs an analysis on it to determine the password length statistics and complexity.
 * If you choose JtR format, output generation as such: john --show <hashes_file> > jtroutput
 * If you chose newline format, one password per line.
''')
parser.add_argument("password_file", help="Password File in jtr or newline format",
                    type=lambda x: is_valid_file(parser, x))
parser.add_argument("-f", help="Input Format", type=str, dest="format", choices=("jtr", "newline"))
parser.add_argument("--basic", help="Run a basic analysis for length and categorization", action='store_true')
parser.add_argument("--zxcvbn", help="Run zxcvbn password strength anayzer: https://github.com/dropbox/zxcvbn", action='store_true')
parser.add_argument("--csv", help="Optional CSV Output to graph in excel", type=str)
args = parser.parse_args()

if not (args.basic or args.zxcvbn):
    parser.error('No action requested, add --basic or --zxcvbn')

class BColors:
    '''terminal colors: http://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python'''
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
f = BColors.FAIL + "[x]" + BColors.ENDC
g = BColors.OKGREEN + "[+]" + BColors.ENDC
i = BColors.WARNING + "[i]" + BColors.ENDC

if args.csv:
    import csv
    if os.path.isfile(args.csv):
        overwrite = input("%s %s exists, overwrite (y/N): " %(f, args.csv))
        if overwrite.upper() != "Y":
            quit()
    csv_file = open(args.csv, 'w')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Command Used", " ".join(sys.argv)])
    csv_writer.writerow([]) #newline

if args.zxcvbn:
    try:
        #https://github.com/dropbox/python-zxcvbn
        import zxcvbn
    except ImportError:
        quit(f+" zxcvbn module missing. pip install git+https://github.com/moreati/python-zxcvbn.git")
    except SyntaxError:
        quit(f+" zxcvbn repo edition installed.  This is not py3 compatible.  "+
             "Please install version from PR. pip install git+https://github.com/moreati/python-zxcvbn.git")

class BasicAnalysis():
    '''Holds the basic analysis of length and category'''
    def __init__(self, password="", password_category=0):
        self.password = password
        self.password_category = password_category
        self.length = len(password)

    def categorize(self, username=''):
        '''Determine a rough categorization of complexity'''
        if username == self.password:
            self.password_category = 0
        elif re.match('^[a-z]+$', self.password):
            self.password_category = 1
        elif re.match('^[a-zA-Z]+$', self.password):
            self.password_category = 2
        elif re.match('^[a-zA-Z0-9]+$', self.password):
            self.password_category = 3
        else:
            self.password_category = 4

class ScoreRun():
    '''Class to hold the scores of a password'''
    def __init__(self, password='', username=''):
        if args.basic:
            self.basic = BasicAnalysis(password)
            self.basic.categorize(username)
        if args.zxcvbn:
            try:
                self.zxcvbn = zxcvbn.password_strength(password)
                #save memory on objects we dont use
                self.zxcvbn = {"crack_time":self.zxcvbn["crack_time"], "score":self.zxcvbn["score"]}
            except OverflowError:
                raise OverflowError #pass it back down, and we'll ignore this one.

analyzed = []
with ProgressBar(max_value=sum(1 for line in open(args.password_file, 'r', encoding="latin-1"))) as bar:
    with open(args.password_file, 'r', encoding="latin-1") as password_file:
        progress_bar_counter = 0
        print(g, "Starting Password Analysis")
        for line in password_file:
            progress_bar_counter += 1
            bar.update(progress_bar_counter)
            if args.format == "jtr" and not ":" in line: #skip any line that doesnt contain a valid un:pass for jtr files
                continue
            if args.format == "jtr":
                username = line.split(":")[0]
                password = ''.join(line.split(":")[1:]).strip()
            else:
                password = line.strip()
                username = ""
            try:
                analyzed.append(ScoreRun(password, username))
            except OverflowError:
                pass

if args.basic:
    print(g, "Basic Analysis")
    print("  Password Length Analysis")
    csv_writer.writerow(["Password Length Analysis"])
    lengths = [p.basic.length for p in analyzed]
    length_mean = locale.format("%0.2f", numpy.mean(lengths), grouping=True)
    print("  Average Length:", length_mean, "characters")
    csv_writer.writerow(["Password Length Average", length_mean])
    lengths_count = Counter(lengths)
    csv_writer.writerow(["Password Length", "Count", "Percentage of Total"])
    for l in sorted(lengths_count):
        print('    %s:' %(l),
              locale.format("%0.0f", lengths_count[l], grouping=True),
              "(" + locale.format("%0.2f", numpy.mean(lengths_count[l]/len(lengths)*100), grouping=True) + "%)")
        csv_writer.writerow([l,
                             '"' + locale.format("%0.0f", lengths_count[l], grouping=True) + '"',
                             locale.format("%0.2f", numpy.mean(lengths_count[l]/len(lengths)*100), grouping=True)])
    del lengths
    del lengths_count
    complexity = [p.basic.password_category for p in analyzed]
    complexity_average = locale.format("%0.2f", numpy.mean(complexity), grouping=True)
    print("  Average Complexity:", complexity_average + "/4")
    print("  Password Complexity Analysis")
    csv_writer.writerow([]) #spacer
    csv_writer.writerow(["Average Complexity", complexity_average])
    complexity_count = Counter(complexity)
    password_category_verbose = ['Username is Password', 'alphaLower', 'alphaMixed', 'alphaNum', 'alphaNumSpecial']
    for c in password_category_verbose:
        print('    %s:' %(c),
              locale.format("%0.0f", complexity_count[password_category_verbose.index(c)], grouping=True),
              "(" + locale.format("%0.2f", numpy.mean(complexity_count[password_category_verbose.index(c)]/len(complexity))*100,
                                  grouping=True) + "%)")
        csv_writer.writerow(["%s" %(c),
                             '"' + locale.format("%0.0f", complexity_count[password_category_verbose.index(c)], grouping=True) + '"',
                             locale.format("%0.2f",
                                           numpy.mean(complexity_count[password_category_verbose.index(c)]/len(complexity))*100,
                                           grouping=True) + "%"])
    del complexity
    del complexity_count

if args.zxcvbn:
    print(g, "zxcvbn Analysis")
    csv_writer.writerow([]) #spacer
    csv_writer.writerow(["zxcvbn Analysis"]) #spacer
    crack_time = [p.zxcvbn["crack_time"] for p in analyzed]
    crack_time_average = locale.format("%0.2f", numpy.mean(crack_time), grouping=True)
    print('  zxcvbn Crack Time Average:', crack_time_average, "seconds")
    csv_writer.writerow(['zxcvbn Crack Time Average', crack_time_average])
    #this section is only valid in the JS version of zxcvbn
    # crackSeconds = [p.zxcvbn["crack_time_seconds"] for p in analyzed]
    # print("zxcvbn Average Crack Time", "{0:.2f}%".format(numpy.mean(crackSeconds)))
    # csv_writer.writerow(["zxcvbn Average Crack Time", "{0:.2f}%".format(numpy.mean(crackSeconds))])
    scores = [p.zxcvbn["score"] for p in analyzed]
    scores_average = locale.format("%0.2f", numpy.mean(scores), grouping=True)
    print('  zxcvbn Score Average:', scores_average)
    csv_writer.writerow(['zxcvbn Score Average', scores_average])
    print("  zxcvbn Password Scores Analysis")
    csv_writer.writerow(["zxcvbn Password Scores Analysis"])
    score_counter = Counter(scores)
    score_counter_verbose = ['too guessable', 'very guessable', 'somewhat guessable',
                             'safely unguessable', 'very unguessable']
    for k in score_counter_verbose:
        print('    %s:' %(k),
              locale.format("%0.0f", score_counter[score_counter_verbose.index(k)], grouping=True),
              "(" + locale.format("%0.2f", score_counter[score_counter_verbose.index(k)]/len(scores)*100, grouping=True) + "%)")
        csv_writer.writerow(["%s:" %(k),
                             '"' + locale.format("%0.0f", score_counter[score_counter_verbose.index(k)], grouping=True) + '"',
                             locale.format("%0.2f", score_counter[score_counter_verbose.index(k)]/len(scores)*100, grouping=True) + "%"])
    del scores
    del score_counter

if args.csv:
    csv_file.close()