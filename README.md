# Deprecated
https://github.com/digininja/pipal

# Password-Strength-Analyzer
Analyze password strengths of compromised database users

## Story
While working on a pentest, I was able to compromise the DB and get 5k MD5 hashes.  In 24hrs, I was able to crack 4k of those hashes.  I needed a way to convey to the client that they should implement a (javascript) password strength meter, or password complexity requirements.  So, I wrote this script (on my own time) to analyze password complexity, for use when comparing to other compromised databases.  For instance, if I can say the average password length is 4.3 characters, vs rockyou's # then there is some factual information that can make an action.

## WIP
This is a work in progresss, as I get time to increase functionality and the features.  My hope is to do a base analysis (average length, lower case, vs mixed case, vs special characters etc), as well as utilized a few JS strength meters to get a score that more complexity.  I think adding JS complexity scores is also nice since that is one possible solutino for a client.

## Example
```
[+] Basic Analysis
  Password Length Analysis
  Average Length: 5.65 characters
    1: 2 (0.06%)
    3: 2 (0.06%)
    4: 1,412 (39.75%)
    5: 602 (16.95%)
    6: 406 (11.43%)
    7: 342 (9.63%)
    8: 556 (15.65%)
    9: 192 (5.41%)
    10: 22 (0.62%)
    11: 8 (0.23%)
    12: 6 (0.17%)
    15: 2 (0.06%)
  Average Complexity: 1.67/4
  Password Complexity Analysis
    Username is Password: 46 (1.30%)
    alphaLower: 2,228 (62.73%)
    alphaMixed: 146 (4.11%)
    alphaNum: 1,128 (31.76%)
    alphaNumSpecial: 4 (0.11%)
[+] zxcvbn Analysis
  zxcvbn Crack Time Average: 7,587.34 seconds
  zxcvbn Score Average: 0.05
  zxcvbn Password Scores Analysis
    too guessable: 3,424 (96.40%)
    very guessable: 100 (2.82%)
    somewhat guessable: 24 (0.68%)
    safely unguessable: 4 (0.11%)
    very unguessable: 0 (0.00%)
```
