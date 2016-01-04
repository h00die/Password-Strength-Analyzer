# Password-Strength-Analyzer
Analyze password strengths of compromised database users

## Story
While working on a pentest, I was able to compromise the DB and get 5k MD5 hashes.  In 24hrs, I was able to crack 4k of those hashes.  I needed a way to convey to the client that they should implement a (javascript) password strength meter, or password complexity requirements.  So, I wrote this script (on my own time) to analyze password complexity, for use when comparing to other compromised databases.  For instance, if I can say the average password length is 4.3 characters, vs rockyou's # then there is some factual information that can make an action.

## WIP
This is a work in progresss, as I get time to increase functionality and the features.  My hope is to do a base analysis (average length, lower case, vs mixed case, vs special characters etc), as well as utilized a few JS strength meters to get a score that more complexity.  I think adding JS complexity scores is also nice since that is one possible solutino for a client.
