#!/usr/bin/env bash



##########################################################################################################
#Author: Abraxas
#Created: 09.10.2021 0319
#Last Modified: 
##########################################################################################################

#bash -n script.sh 		# dry run for syntax
#bash -v scripts.sh 	# trace
#bash -x scripts.sh 	# more vergbose trace


##make a temp dir as working dir
##add script lock


##########################################################################################################
# Initial Setup
##########################################################################################################


#Fail safe
set -o errexit # fail on exit
set -o nounset # fail on variable issues
set -o pipefail # fail for pipe related stuff


# magic variables
script_init()
{
	readonly orig_cwd="$PWD"
  readonly script_path="${BASH_SOURCE[0]}"
  readonly script_params="$*"
	script_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd -P )"	# resolve, doesn't work with sym links
  script_name="$(basename "$script_path")"
  readonly script_dir script_name
  # error_log
  touch /tmp/error_log.out
}

# Logging
## colors and styff
bold=$(tput bold)
underline=$(tput sgr 0 1)
reset=$(tput sgr0)

red=$(tput setaf 1)
green=$(tput setaf 76)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
magenta=$(tput setaf 5)
cyan=$(tput setaf 6)
white=$(tput setaf 7)
purple=$(tput setaf 171)

## logging actual with args
lheader(){ printf "\n${bold}${purple}==========  %s  ==========${reset}\n" "$@" ; }
lfinish(){ printf "${magenta}➜ %s${reset}\n" "$@\n"; }
lecho(){ printf "${green} %s${reset}\n" "$@"; }
lerror(){ printf "${red} %s${reset}\n" "$@"; }
lwarning(){ printf "${yellow}➜ %s${reset}\n" "$@" ; }
lunderline(){ printf "${cyan}${underline}${bold}%s${reset}\n" "$@"; }
lbold(){ printf "${white}${bold}%s${reset}\n" "$@"; }
lnote(){ printf "${underline}${bold}${blue}Note:${reset}  ${blue}%s${reset}\n" "$@"; }
lseperate(){ printf "${magenta}---${reset}\n"; }
msg() { echo >&2 -e "${1-}"; }

die() 
{
  local msg=$1
  local code=${2-1} # default exit status 1 # research on non zero exit codes
  msg "$msg"
  msg "$code"
  exit "$code"
}

#Trap and script cleanup
trapCleanup() 
{
	#add cleanup
	#add logging
	lheader "Terminated due to an errpr or script exited"
	lnote "Script Name" "$script_name"
	lseperate
	lwarning "Script Path:" "$script_path"
	lseperate
	lwarning "Script execution Path:" "$orig_cwd"
	lseperate
	lwarning "Script Parameters:" "$script_params"
	lseperate
	lwarning "Script dir:" "$script_dir"
	#
	die "Trapped."
}


# usage
usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [-f] -p param_value arg1 [arg2...]

Script description here.

...
EOF
  exit
}



##########################################################################################################
# Functions actual
##########################################################################################################
##########################################################################################################




##########################################################################################################
# Prelimnery installs
##########################################################################################################

# update
apt_update()
{
	apt update -y
	lfinish "Done updating"
}
apt_fullUpgrade()
{
	apt full-upgrade -y
	apt_update
	lfinish "Done Upgrading"
}

apt_fix()
{
	apt install --fix-missing
	apt auto-remove
	lfinish "Done fixing"
}

update_everything()
{
	apt_update
	apt_fullUpgrade
	apt_fix
}

# basic essentials
install_essentials()
{
	apt install apt-transport-https curl -y 
	#apt install dkms build-essential linux-headers-amd64 -y
	lfinish "Done with basic essentials"
}

# Sublime Text3
install_sublime()
{
	lecho "Installing Sublime"
	wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | apt-key add -
	echo "deb https://download.sublimetext.com/ apt/stable/" | tee /etc/apt/sources.list.d/sublime-text.list
	apt update
	apt install sublime-text
	lfinish "Installed Sublime-text"
}

# Brave
install_brave()
{
	lecho "Installing Brave-Browser"
	curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
	echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main"| tee /etc/apt/sources.list.d/brave-browser-release.list
	apt update
	apt install brave-browser
	lfinish "Done"
}

# docker
install_docker() 
{
	if ! [ -x "$(command -v docker)" ]
	then
		lecho "Installing Docker.."
		curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add - >/dev/null 2>&1
		echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
		apt-get update >/dev/null 2>&1
		apt-get install docker-ce -y >/dev/null 2>&1
		lfinish "Docker Installed"

	else
		lwarning "A pervious version of docker appears to be installed already! Reinstalling docker-ce..."$
		apt-get remove docker docker-engine docker.io >/dev/null 2>&1
		apt-get install docker-ce -y >/dev/null 2>&1
		lecho "Done"
	fi
}

# GoLang
install_go() 
{
	if ! [ -x "$(command -v go)" ]
	then
  	lecho "Installing golang"
    apt install golang -y >/dev/null 2>/tmp/error_log.out 
	else
    lunderline "Go already installed"
	fi
}

#Python-pip
install_pip() 
{
	if ! [ -x "$(command -v pip)" ]
	then
		lecho "Installing pip"
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py >/dev/null 2>/tmp/error_log.out
    python get-pip.py >/dev/null 2>/tmp/error_log.out
    rm get-pip.py
    lfinish "pip installed"
  else
  	lunderline "PIP already installed"
	fi
}

# Python3-pip
install_pip3()
{
	if ! [ -x "$(command -v pip3)" ]
	then
		lecho "Installing pip3"
		apt install python3-pip -y >/dev/null 2>/tmp/error_log.out
		lfinish "PIP23 Installed"
	else
		lunderline "PI3 already installed"
	fi

}

# pipx -> python venv
install_pipx()
{
	# add pipx
	if ! [ -x "$(command -v pipx)" ]
	then
		lecho "Installing pipx"
		pip3 install pipx
		apt install python3-venv -y 
		pipx ensurepath
		source $HOME/.bashrc
		source /home/$SUDO_USER/.bashrc
		pipx run cowsay "PIPX is Awesome!!!"

		#need to find a proper fix for this
		#pipx install cowsay
		#sudo -u "$SUDO_USER" pipx install cowsay

		lfinish "Pipx Installed"

	else
		lunderline "Pipx already Installed"
	fi

}

# Terminator
install_terminator()
{
	if ! [ -x "$(command -v terminator)" ]
	then
		lecho "Installing Terminator"
		apt install terminator -y
	else
		lunderline "Terminator already Installed"
	fi
}

# Add tmux for headless mode
##########################################################################################################
# Tools
##########################################################################################################


# FFuf
install_ffuf()
{
	if ! [ -x "$(command -v ffuf)" ]
	then
		lecho "Installing FFuf"
		cd /opt
		#mkdir ffuf #test and comment this 
		#go get -u github.com/ffuf/ffuf
		git clone https://github.com/ffuf/ffuf.git >/dev/null 2>/tmp/error_log.out
		cd ffuf
		go get
		go build 1> /dev/null
		ln -sf /opt/ffuf/ffuf /usr/local/bin/ffuf
		lfinish "Fluff Installed"
	else
		lunderline "Ffuf already installed"
	fi
}

# Dirsearch -> recursive
# test -> sudo -u "$SUDO_USER" pipx list | grep
install_dirsearch()
{
	if ! [ -x "$(command -v dirsearch)" ]
	then
		lecho "Installing dirsearch"
		sudo -u $SUDO_USER pipx install dirsearch
		lfinish "DirSearch installed"
	else
		lunderline "Dirsearch already exists"
	fi	
}

# Gobuster -> non recursive
install_gobuster()
{
	if ! [ -x "$(command -v gobuster)" ]
	then
		lecho "Installing dirsearch"
		cd /opt
		go install github.com/OJ/gobuster/v3@latest
		lfinish "Gobuster Installed"
	else
		lunderline "Gobuster already exists"
	fi

}


# GTFO Lookup
install_gtfoblookup()
{
	dir=/opt/GTFOBLookup
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so GTFO already installed"
	else
		lecho "Installing GTFOBLookup"
		cd /opt/
		git clone https://github.com/nccgroup/GTFOBLookup.git
		cd GTFOBLookup
		pip3 install -r requirements.txt >/dev/null 2>/tmp/error_log.out
		python3 gtfoblookup.py update >/dev/null 2>/tmp/error_log.out
		#add sym link to /bin
		lfinish "GTFO Installed"
	fi
}

# Reverse shell generator
install_rsg() 
{
	if ! [ -x "$(command -v rsg)" ]
	then
		lecho "Installing Reverse Shell Generator#"
		cd /opt/
		git clone https://github.com/mthbernardes/rsg.git
		cd rsg
		sh install.sh 
		lfinish "rsg installed"
	else
		lunderline "RSG alredy Installed"
	fi
}


# GAU

install_gau()
{
	dir=/opt/gau
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so gau alredy installed"
	else
		cd /opt/
		GO111MODULE=on go get -u -v github.com/lc/gau
		lfinish "gau installed"
	
	fi
}

# Tiberius AutoRecon -> need to add dependancies here
install_autorecon()
{
	dir=/opt/AutoRecon
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so Autorecon alredy installed"
	else
		cd /opt/
		install_autorecon_dependancies
		sudo -u $SUDO_USER pipx install git+https://github.com/Tib3rius/AutoRecon.git
		lfinish "AutoRecon installed with pipx"
	
	fi
}

install_autorecon_dependancies()
{
	lecho "Add stuff here"
}

# search-that-hash
install_sth()
{
	if ! [ -x "$(command sth)" ]
	then
		lecho "Installing Search-that-hash"
		sudo -u $SUDO_USER pipx install search-that-hash
		lfinish "STH Installed"
	else
		lunderline "STH already exists"
	fi
}

# name-that-hash
install_nth()
{
	if ! [ -x "$(command -v nth)" ]
	then
		lecho "Installing Search-that-hash"
		sudo -u $SUDO_USER pipx install namne-that-hash
		lfinish "NTH Installed"
	else
		lunderline "NTH already exists"
	fi
}

# Haiti
install_haiti()
{
	if ! [ -x "$(command -v haiti)" ]
	then
		lecho "Installing Search-that-hash"
		sudo apt install rubygems
		sudo gem install haiti-hash
		lfinish "haiti Installed"
	else
		lunderline "Haiti already exists"
	fi
}

# hash-id
install_hashid()
{
	if ! [ -x "$(command -v hashid)" ]
	then
		lecho "Installing hash-id"
		sudo apt install hashid
		lfinish "Hash-Id Installed"
	else
		lunderline "hash0d already exists"
	fi
}

# hashcat
install_hashcat()
{
	if ! [ -x "$(command -v hashcat)" ]
	then
		lecho "Installing hashcat"
		
		apt-get -qq install cmake build-essential -y 
		apt-get -qq install checkinstall git -y
		cd /opt 
		git clone https://github.com/hashcat/hashcat.git >/dev/null 2>/tmp/error_log.out
		cd hashcat && git submodule update --init && make && make install >/dev/null 2>/tmp/error_log.out
		hashcat --version

		lfinish "Hashcat Installed"
	else
		lunderline "hashcat already exists"
	fi
}

# JohnTheRipper
install_jtr()
{
	if ! [ -x "$(command -v john)" ]
	then
		lecho "Installing JTR"
		sudo apt install john -y
		lfinish "JTR Installed"
	else
		lunderline "JTR already exists"
	fi


	dir=/opt/JohnTheRipper
	if !  [ -d "$dir" ]
	then
		lecho "Cloning repo"
		cd /opt 
		git clone git://github.com/magnumripper/JohnTheRipper
	fi

}

# ciphey
install_ciphey()
{
	if ! [ -x "$(command -v ciphey)" ]
	then
		lecho "Installing ciphey"
		sudo -u $SUDO_USER pipx install ciphey
		lfinish "STH Installed"
	else
		lunderline "STH already exists"
	fi
}

# Windows Exploit suggestor
install_wesng(){
	dir=/opt/wesng
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> Win ExploitSuggestor alredy installed "
	else
		lecho "Installing WES-NG"
		cd /opt
		git clone https://github.com/bitsadmin/wesng
		lfinish "WES_NG Installed -> wes.py --update"
	fi
	}


# pspy - unprivileged Linux process snooping

# shodan-cli
install_shodan_cli()
{
	if ! [-x "$( command -v shodan)" ]
	then
		lecho "Installing Shodan CLI"
		sudo -u $SUDO_USER pipx install shodan
		lfinish "Shodan CLI Installed"
	else
		lunderline "Shodan already exists"
	fi
}

# GoSpider
## https://github.com/jaeles-project/gospider
install_gospider()
{
	if ! [ -x "$(command -v hashid)" ]
	then
		lecho "Installing GoSpider"
		cd /opt 
		git clone https://github.com/jaeles-project/gospider
		cd ./gospider
		go build 
		cp ./gospider /usr/local/bin/
		lfinish "Hash-Id GoSpier"
	else
		lunderline "GoSpider already exists"
	fi
}

# Sublister
install_sublist3r()
{
	if ! [ -x "$(command -v sublist3r)" ]
	then
		lecho "Installing Sublist3r"
		apt install sublist3r -y
		lfinish "Hash-sublist3r Installed"
	else
		lunderline "Sublister already exists"
	fi
}

# ne04j
##


# bloodhound
##


# evil_winrm
##
install_evil-winrm()
{
	if ! [ -x "$(command -v evil-winrm)" ]
	then
		lecho "Installing Evil-WinRM"
		gem install evil-winrm
		lfinish "Evil-WinRM Installed"
	else
		lunderline "Evil-WinRM already exists"
	fi
}

# stegoVeritas
install_stegoVeritas()
{
	if ! [ -x "$(command -v stegoveritas)" ]
	then
		lecho "SetgoVeritas hash-id"
		sudo -u $SUDO_USER pipx install stegoveritas
		stegoveritas_install_deps
		lfinish "SetgoVeritass and dependancies Installed"
	else
		lunderline "setgoVeritass already exists"
	fi
}

# exif

# crackmapexe -> talk to Raven
## apt install crackmapexec -y


# autoenum git clone 
## https://github.com/Gr1mmie/autoenum.git
## chmod +x autoenum/autoenum.sh
install_grimmie_autoenum()
{
	dir=/opt/autornum
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so autoenum already installed"
	else
		lecho "Installing Grimme's AutoEnum"
		cd /opt/
		git clone https://github.com/Gr1mmie/autoenum.git
		cd autoenum
		chmod +x autoenum.sh
		lfinish "AutoEnum Installed"
	fi
}

# MassScan
## https://github.com/robertdavidgraham/masscan


# Add Github search tools -> see obsidian

# Add those CMS wordlists from the THM room -> obsidian -> https://github.com/ZephrFish/Wordlists


# Add updog

# add the advanced netcat version

# add my edited nmapautomater

# stegseek

# searchsploit
install_searchploit()
{
	dir=/opt/exploitdb
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so Searchsploit alredy installed"
	else
		lecho "Installing Searchsploit"
		cd /opt
		git clone https://github.com/offensive-security/exploitdb.git
		ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
		lfinish "Searchsploit Installed"
	fi
}
# ferox
install_feroxbuster()
{
	dir=/opt/feroxbuster
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so ferox alredy installed"
	else
		lecho "Installing Ferox"
		cd /opt
		git clone https://github.com/epi052/feroxbuster.git
		bash feroxbuster/install-nix.shs
		ln -sf /opt/feroxbuster/feroxbuster /usr/local/bin/feroxbuster
		lfinish "Ferroxbuster Installed"
	fi
}

# Network Miner -> zero's script
## wget https://www.netresec.com/?download=NetworkMiner -O /tmp/nm.zip

# add the audio stego tool -> check obsidian

###### Cheatsheets

# Navi -> Cheatsheet 
install_navi()
{
	dir=/opt/navi
	if [ -d "$dir" ]
	then
		lunderline "$dir exists -> so NAVI alredy installed "
	else
		echo $grn"Installing NAVI and FZF..."$white
		cd /opt/
		# Installing Dependency FZF
		apt install fzf >/dev/null 2>/tmp/error_log.out
		git clone https://github.com/denisidoro/navi.git >/dev/null 2>/tmp/error_log.out
		cd navi
		bash <(curl -sL https://raw.githubusercontent.com/denisidoro/navi/master/scripts/install)
	fi
}

# curl cheat.sh -> includes tldr
## add cheat.sh to alias
# tldr
install_tldr()
{
	if ! [ -x "$(command -v tldr)" ]
	then
		lecho "Installing TLDR"
		apt install tldr -y
		lfinish "tldr Installed"
	else
		lunderline "tldr already exists"
	fi
}


##########################################################################################################
# Scripts and wordlists
##########################################################################################################

# LinEnum

install_linenum()
{
	dir=/opt/LinEnum
	if [ -d "$dir" ]
	then
		lunderline "LinEnum exits"
	else
		lecho "Installing LinENum"
		cd /opt
		git clone https://github.com/rebootuser/LinEnum.git >/dev/null 2>&1
		lfinish "LinEnum Installed"
	fi
}

# LinPEAS
# WinPEAS

install_PEAS()
{
	dir=/opt/privilege-escalation-awesome-scripts-suite
	if [ -d "$dir" ]
	then
		lunderline "PEAS exists -> Priv Esc scripts alrey exist"
	else
		lecho "Installing Privilege Escalation Awesome Scripts Suite"
		cd /opt/
		git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git >/dev/null 2>&1
		lfinish "PEAS Installed"
	fi
}
# Add enum4linux ng
## https://github.com/cddmp/enum4linux-ng.git
install_enum4linux_ng()
{
	dir=/opt/enum4linux-ng
	if [ -d "$dir" ]
	then
		lunderline "enum4linux-ng exists -> enum4linux script alrey exist"
	else
		lecho "Installing Enum4Linux Next Gen"
		cd /opt/
		git clone https://github.com/cddmp/enum4linux-ng
		gc https://github.com/CiscoCXSecurity/enum4linux
		lfinish "enum4linux-ng Installed"
	fi
}

# Add linux msart enumeration -> same as above but better looking output
## https://github.com/diego-treitos/linux-smart-enumeration.git



# hash-identifier python script
## copy from the notebook


# install wordlistctl
install_wordlistctl()
{
	dir=/opt/wordlstctl
	if [ -d "$dir" ]
	then
		lunderline "Wordlistctl alrey exist"
	else
		lecho "Installing Wordlistctl"
		cd /opt/
		gc https://github.com/BlackArch/wordlistctl.git
		lfinish "Wordlistctl installed -> ./wordlistctl/wordlistctl.py [fetch|list|search] <>"
	fi
}

# add seclists
install_seclists()
{
	dir=/usr/share/wordlists/SecLists
	if [ -d "$dir" ]
	then
		lunderline "SecLists Installed"
	else
		lecho "Installing Seclists"
		#cd /tmp
		#git clone https://github.com/danielmiessler/SecLists.git
		#cp -R SecLists /usr/share/wordlists/
		#add alias seclists="cd /usr/share/SecLists"
		sudo apt install seclists
		lfinish "Seclistst Installed"
	fi
}

# extract rockyou.txt

# add dirb and wfuzz list
install_dirblist()
{
	dir=/usr/share/wordlists/dirb
	if [ -d "$dir" ]
	then
		lunderline "Dirb wordList Present"
	else
		lecho "Installing Dirb  wordList"
		cd /tmp
		git clone https://github.com/v0re/dirb.git
		cd dirb
		cp -R wordlists /usr/share/wordlists/dirb
		lfinish "Dirb worlistList Installed"
	fi
}
# add my gCloud cracking hashes python notebook
# add the rsa key cracking python notebook

##########################################################################################################
# Virtual Box stuff
##########################################################################################################

# add guest additions -> headers and such
## -> find something in other scripts
# setup perms for sharedFolder -> add user to vboxsf



##########################################################################################################
##########################################################################################################
##########################################################################################################
# Driver code
##########################################################################################################
##########################################################################################################


main()
{
	trap trapCleanup EXIT INT TERM ERR
	script_init "$@"

	echo "Run as sudo"
	

	#essential
	update_everything
	install_essentials
	install_pip
	install_pip3
	install_pipx
	install_go
	install_docker
	install_terminator


	#Tools
	install_ffuf
	install_dirsearch
	install_gobuster
	install_gtfoblookup
	install_rsg
	install_gau
	#install_autorecon_dependancies
	#install_autorecon
	install_sth
	#install_nth
	install_haiti
	install_hashid
	install_hashcat
	install_jtr
	install_ciphey
	install_wesng
	install_shodan_cli
	#install_gospider
	install_sublist3r
	install_evil-winrm
	install_stegoVeritas
	install_grimmie_autoenum
	install_searchploit
	feroxbuster
	install_navi
	install_tldr

	#Scripts
	install_linenum
	install_PEAS
	install_enum4linux_ng
	install_wordlistctl
	install_seclists
	install_dirblist

	#Docker images


	#Apps
	install_sublime
	install_brave







	# add something for flags etc


}





##########################################################################################################
# fucntion call
##########################################################################################################
##########################################################################################################


#set -x																	# set Debug
# for source issues
if ! (return 0 2> /dev/null); then 
    main "$@"
fi
#set +x																	# unset Debug#!/usr/bin/env bash

