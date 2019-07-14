# First Project: LOGS ANALYSIS

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Intro](#intro)
- [Requirements](#requirements)
- [Installation](#installation)
- [Instruction](#instruction)
- [Files](#file)

## Intro

This project sets up a mock PostgreSQL database for a fictional news website. The provided Python script uses the psycopg2 library to query the database and produce a report that answers the following three questions:

Reporting tool that prints out reports (in plain text) based on the data in the database

1.The most popular three articles of all time

2.The most popular article authors of all time

3.The day which  more than 1% of requests lead to errors

## Requirements	

You'll use a virtual machine (VM) to run an SQL database server and a web app that uses it. The VM is a Linux server system that runs on top of your own computer. You can share files easily between your computer and the VM; and you'll be running a web service inside the VM which you'll be able to access from your regular browser.

We're using tools called [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1) to install and manage the VM. You'll need to install these to do some of test. The instructions on this page will help you do this.

You can also use :

Python 3.4
PostgreSQL
psycopg2
 
to run the app

## Installation

### Install VirtualBox

VirtualBox is the software that actually runs the virtual machine. [You can download it from virtualbox.org, here.](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1) Install the _platform package_ for your operating system. You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it; Vagrant will do that.

Currently (October 2017), the supported version of VirtualBox to install is version 5.1. Newer versions do not work with the current release of Vagrant.

**Ubuntu users:** If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center instead. Due to a reported bug, installing VirtualBox from the site may uninstall other software you need.

### Install Vagrant

Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. [Download it from vagrantup.com.](https://www.vagrantup.com/downloads.html) Install the version for your operating system.

**Windows users:** The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

![vagrant --version](https://d17h27t6h515a5.cloudfront.net/topher/2016/December/584881ee_screen-shot-2016-12-07-at-13.40.43/screen-shot-2016-12-07-at-13.40.43.png)

_If Vagrant is successfully installed, you will be able to run_ `vagrant --version`
_in your terminal to see the version number._
_The shell prompt in your terminal may differ. Here, the_ `$` _sign is the shell prompt._

### Download the VM configuration

Use Github to fork and clone, or download, the repository [https://github.com/udacity/fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm).

You will end up with a new directory containing the VM files. Change to this directory in your terminal with `cd`. Inside, you will find another directory called **vagrant**. Change directory to the **vagrant** directory:

![vagrant-directory](https://d17h27t6h515a5.cloudfront.net/topher/2016/December/58487f12_screen-shot-2016-12-07-at-13.28.31/screen-shot-2016-12-07-at-13.28.31.png)

_Navigating to the FSND-Virtual-Machine directory and listing the files in it._
_This picture was taken on a Mac, but the commands will look the same on Git Bash on Windows._

## Instructions

### Start the virtual machine

From your terminal, inside the **vagrant** subdirectory, run the command `vagrant up`. This will cause Vagrant to download the Linux operating system and install it. This may take quite a while (many minutes) depending on how fast your Internet connection is.

![vagrant-up-start](https://d17h27t6h515a5.cloudfront.net/topher/2016/December/58488603_screen-shot-2016-12-07-at-13.57.50/screen-shot-2016-12-07-at-13.57.50.png)

_Starting the Ubuntu Linux installation with `vagrant up`._
_This screenshot shows just the beginning of many, many pages of output in a lot of colors._

When `vagrant up` is finished running, you will get your shell prompt back. At this point, you can run `vagrant ssh` to log in to your newly installed Linux VM!

![linux-vm-login](https://d17h27t6h515a5.cloudfront.net/topher/2016/December/58488962_screen-shot-2016-12-07-at-14.12.29/screen-shot-2016-12-07-at-14.12.29.png)

_Logging into the Linux VM with `vagrant ssh`._

### Logged in

If you are now looking at a shell prompt that starts with the word `vagrant` (as in the above screenshot), congratulations — you've gotten logged into your Linux VM.

### The files for this test

Inside the VM, change directory to `/vagrant` and look around with `ls`.

The files you see here are the same as the ones in the `vagrant` subdirectory on your computer (where you started Vagrant from). Any file you create in one will be automatically shared to the other. This means that you can edit code in your favorite text editor, and run it inside the VM.

Files in the VM's `/vagrant` directory are shared with the `vagrant` folder on your computer. But other data inside the VM is not. For instance, the PostgreSQL database itself lives only inside the VM.

### Running the database

The PostgreSQL database server will automatically be started inside the VM. You can use the `psql` command-line tool to access it and run SQL statements:

![linux-vm-PostgreSQL](https://d17h27t6h515a5.cloudfront.net/topher/2016/December/58489186_screen-shot-2016-12-07-at-14.46.25/screen-shot-2016-12-07-at-14.46.25.png)

_Running `psql`, the PostgreSQL command interface, inside the VM._
You will need to download the sql file. 
◦you could use our  compressed (e.g. zipped) version of newsdata.sql in our repository.Or use this link :
◦https://d17h27t6h515a5.cloudfront.net/topher/2016/August/57b5f748_newsdata/newsdata.zip

So, you run this command to install sql file.

To load the data, cd into the vagrant directory and use the command psql -d news -f newsdata.sql.

Here's what this command does:

psql — the PostgreSQL command line program

-d news — connect to the database named news which has been set up for you

-f newsdata.sql — run the SQL statements in the file newsdata.sql

Running this command will connect to your installed database server and execute the SQL commands in the downloaded file, creating tables and populating them with data.

Once you have the data loaded into your database, connect to your database using psql -d news and explore the tables using the \dt and \d table commands and select statements.

\dt — display tables — lists the tables that are available in the database.

\d table — (replace table with the name of a table) — shows the database schema for that particular table.

Get a sense for what sort of information is in each column of these tables.

The database includes three tables:

The 'authors' table includes information about the authors of articles.

The 'articles' table includes the articles themselves.

The 'log' table includes one entry for each time a user has accessed the site.

As you explore the data, you may find it useful to take notes! 

### Run the app

Use `python newsdata-txt.py` inside the VM._ The result is in result.txt.
Use `python newsdata.py` inside the VM._ The result is in web page.
### Logging out and in

If you type `exit` (or `Ctrl-D`) at the shell prompt inside the VM, you will be logged out, and put back into your host computer's shell. To log back in, make sure you're in the same directory and type `vagrant ssh` again.

If you reboot your computer, you will need to run `vagrant up` to restart the VM.
##  file 

 --newsdata.py using flask to display the results
 
 --newsdatadb.py, the programm witch make request from psql to fetch results and display it in web page
 --newsdatadb-txt.py,the programm witch make request from psql to fetch results and display it in plaintext
 
 --app.css is the template style file
 
 --results.txt is the resluts from requests hold on plain text
 
 The installation and instruction is a part of udacity.
 
[(Back to TOC)](#table-of-contents)
