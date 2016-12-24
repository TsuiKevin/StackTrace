#!/usr/bin/env python
#python script for android tombstone file parser

import getopt
import os
import re
import string
import sys
import getpass
import urllib
import shlex,subprocess

ADDR2LINE = 'arm-eabi-addr2line -f -e'

def execute_blocked(cmd):
    proc = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out,err = proc.communicate()
    if proc.returncode == 0:
        return out
    else:
        return err

def addr2line(path,lib,addr):
    if lib != "":
        cmd =  ADDR2LINE + path + lib + " 0x" + addr
        out = execute_blocked(cmd)
        return out
    else:
        return "Not lib defined"

def unwind_backtrace(path,backtrace,outputfile):
    for line,addr,lib in backtrace:
        out = addr2line(path,lib,addr)
        outputfile.write(line)
        outputfile.write(out)

def comments_stack(stack,maps):
    pass

def parser_file(inputfile,outputfile,symbol_path):

    FINGERPRINT_LINE = re.compile(".*Build fingerprint:\s'(?P<fingerprint>.*)'")
    PROCESS_INFO_LINE = re.compile(".*(pid: ([0-9]+), tid: ([0-9]+).*)")
    SIGNAL_LINE = re.compile(".*(signal [0-9]+ \(.*\).*)")
    REGISTER_LINE = re.compile(".*([0-9a-z]{2}) ([0-9a-f]{8})[ ]+([0-9a-z]{2}) ([0-9a-f]{8})[ ]+([0-9a-z]{2}) ([0-9a-f]{8})[ ]+([0-9a-z]{2}) ([0-9a-f]{8})")
    BACKTRACE_LINE = re.compile("(.*)\#([0-9]+)  (..) ([0-9a-f]{3})([0-9a-f]{5})  ([^\r\n \t]*)")
    STACK_LINE = re.compile("(.*)([0-9a-f]{2})([0-9a-f]{6})  ([0-9a-f]{3})([0-9a-f]{5})  ([^\r\n \t]*)")
    THREAD_LINE = re.compile("(.*)(\-\-\- ){15}\-\-\-")
    MAP_LINE = re.compile("")
    
    regs = []
    bt = []
    sk = []
    maps = []
    found_backtrace = False
    for line in inputfile.readlines():
        if FINGERPRINT_LINE.search(line):
            #print FINGERPRINT_LINE.match(line).groups()
            continue
        elif PROCESS_INFO_LINE.search(line):
            #print PROCESS_INFO_LINE.match(line).groups()
            continue
        elif SIGNAL_LINE.search(line):
            #print SIGNAL_LINE.match(line).groups()
            continue
        elif REGISTER_LINE.search(line):
            #print REGISTER_LINE.match(line).groups()
            #match = REGISTER_LINE.match(line)
            #groups = match.groups()
            #for i in range(4):
            #    regs.append((groups[2*i],groups[2*i+1]))
            #print 'match'
            #print groups
            #print groups[0]
        elif BACKTRACE_LINE.search(line):
            found_backtrace = True
            match = BACKTRACE_LINE.match(line)
            groups = match.groups()
            bt.append((line,groups[3]+groups[4],groups[5]))
        elif STACK_LINE.search(line):
            match = STACK_LINE.match(line)
            groups = match.groups()
            sk.append((line,groups[1]+groups[2],groups[3]+groups[4])) 
        elif MAP_LINE.search(line):
            match = MAP_LINE.match(line)
            groups = match.groups()
            maps.append((line,groups[],groups[]))
        else:
            if found_backtrace == True:
                break

    unwind_backtrace(symbol_path,bt,outputfile)
    comments_stack(st,maps)

def usage():
    print
    print "  Usage: " + sys.argv[0] + " [options] [FILE]"
    print
    print "  -s|--symbols=path"
    print "       default=pwd"
    print "       the path to a symbols dir, such as out/target/product/dream/symbols"
    print
    print "  -o|--output=filename"
    print "       default=stdout"
    print "       the filename for analyze result out put"
    print
    print "  FILE should contain a stack trace in it somewhere"
    print "       the tool will find the stack and convert to "
    print "       address to function:file:line"
    print "       source files and line numbers.  If you don't"
    print "       pass FILE, or if file is -, it reads from"
    print "       stdin."
    print
    sys.exit(1)

def main():
    try:
        options, arguments = getopt.getopt(sys.argv[1:], "",
                             ["s","o","h","symbols=","output=","help"])
    except getopt.GetoptError, error:
        usage()
    
    symbol = "."
    remote = ""
    output = ""
    for option, value in options:
        if option == "-h" or option == "--help":
            usage()
        elif option == "-s" or option == "--symbols":
            symbol = value
        elif option == "-o" or option == "--output":
            output = value

    if len(arguments) > 1:
        usage()

    if len(arguments) == 0 or arguments[0] == "-":
        print "Please input native crash log:  (eof = Ctrl+d)"
        inputfile = sys.stdin
    else:
        print "Searching for native crashes in %s" % arguments[0]
        inputfile = open(arguments[0], "r")

    outputfile = sys.stdout
    if output != "":
        outputfile = open(output,"w")
    
    parser_file(inputfile,outputfile,symbol)

    inputfile.close()
    outputfile.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
