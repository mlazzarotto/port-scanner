# port-scanner
<h3 align="center">Port Scanner</h3>

  <p align="center">
    A simple TCP port scanner written in Python 3
</p>

## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Installation](#installation)
* [Usage](#usage)

<!-- ABOUT THE PROJECT -->
## About The Project

This is a simple TCP Port Scanner written in Python 3.9.
I know there are tons of tools like this, but I just wanted to improve my Python's skills.

### Built With

* [Python 3.9](www.python.org)

## Getting Started
### Installation
Clone the repo
```sh
git clone https://github.com/mlazzarotto/port-scanner.git
```

## Usage
```sh
python main.py -p 80,20-25,443 192.168.1.1
```

```sh
python main.py --port 80,20-25,443 192.168.1.1
```
