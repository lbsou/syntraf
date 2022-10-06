#!/bin/bash

###################################################################
# Script Name	:   install.sh                                                                                       
# Description	:   Install script for SYNTRAF                                                                          
# Args          :   None                                                                                     
# Author       	:	Louis-Berthier Soullière                                    
# Email         :	shadow131@hotmail.com                                      
###################################################################

installer_version=0.1
syntraf_version=
python_min_req_version=3.9
iperf3_min_req_version=3.10
python_env_dir="syntraf-python-env"
repo="https://github.com/lbsou/syntraf.git"
python3_tarball="https://www.python.org/ftp/python/3.10.6/Python-3.10.6.tgz"
iperf3_tarball="https://github.com/esnet/iperf/archive/refs/tags/3.11.tar.gz"
syntraf_tarball="https://github.com/lbsou/syntraf/archive/refs/tags/latest.tar.gz"
base_dir_for_packages="/opt"
default_syntraf_install_dir="${base_dir_for_packages}/syntraf/"

#Global variables (do not change)
readonly cwd=$(pwd)
readonly script_params="$*"
readonly script_path="${BASH_SOURCE[0]}"
script_dir="$(dirname "$script_path")"
script_name="$(basename "$script_path")"
readonly script_dir script_name
	
syntraf_install_dir=

python_installed=
python_version_raw=
python_version=
python_major_version=
python_binary_path=`command -v python3`

pip_binary_path=pip3

iperf3_detected_version=

os_dist=
os_pseudo=
os_rev=
os_distroBasedOn=

client_or_server=

git_installed="False"
git_binary_path=`command -v git`

random_token=`cat /dev/urandom | tr -dc '[:alnum:]' | fold -w ${1:-100} | head -n 1`

# Color variables
green='\033[0;32m'
red='\033[0;31m'
yellow='\033[0;33m'
cyan='\033[0;36m'
blue='\033[0;34m'
magenta='\033[0;35m'
lgreen='\e[1;32m'
clear='\033[0m'

# SYNTRAF Wizard GLOBAL
IPERF3_BINARY_PATH=`command -v iperf3`
WATCHDOG_CHECK_RATE=2

# SYNTRAF Wizard SERVER
SERVER=
SERVER_PORT="6531"
TOKEN=
MESH_LISTENERS_PORT_RANGE=

#SYNTRAF Wizard CLIENT
CLIENT_UID=
SERVER=
TOKEN=

display_banner() {

echo -e "${lgreen}"
echo "_________________________________________________________________"
echo ""
echo " ######  ##    ## ##    ## ######## ########     ###    ######## "
echo "##    ##  ##  ##  ###   ##    ##    ##     ##   ## ##   ##       "
echo "##         ####   ####  ##    ##    ##     ##  ##   ##  ##       "
echo " ######     ##    ## ## ##    ##    ########  ##     ## ######   "
echo "      ##    ##    ##  ####    ##    ##   ##   ######### ##       "
echo "##    ##    ##    ##   ###    ##    ##    ##  ##     ## ##       "
echo " ######     ##    ##    ##    ##    ##     ## ##     ## ##       "
echo ""                                   
echo -e "Have a nice troubleshooting!        ${red}/\        /\ ${clear}            "
echo -e "${lgreen}___________________________________${red}/  \  _/\_/  \ ${clear}${lgreen} ______________"
echo -e "                                       ${red}\/        \/${clear}              "
echo -e "${lgreen}Installer version ${installer_version}${clear}\n"
echo -e "${clear}"
}

function script_usage() {
    cat << EOF
Usage:
     -h|--help                  Displays this help
     -v|--verbose               Displays verbose output
EOF
}

check_if_root() {
	if [ "$EUID" -ne 0 ]; then
	  /usr/bin/printf "${red}Please run this install script as root.${clear}"
	  exit
	fi
} 

detect_os() {
	if [ -f /etc/redhat-release ] ; then
		os_distroBasedOn='RedHat'
		os_dist=`cat /etc/redhat-release |sed s/\ release.*//`
		os_pseudo=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
		os_rev=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
	elif [ -f /etc/SuSE-release ] ; then
		os_distroBasedOn='SuSe'
		os_pseudo=`cat /etc/SuSE-release | tr "\n" ' '| sed s/VERSION.*//`
		os_rev=`cat /etc/SuSE-release | tr "\n" ' ' | sed s/.*=\ //`
	elif [ -f /etc/mandrake-release ] ; then
		os_distroBasedOn='Mandrake'
		os_pseudo=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
		os_rev=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
	elif [ -f /etc/debian_version ] ; then
		os_distroBasedOn='Debian'
		if [ -f /etc/os-release ] ; then
			os_dist=`cat /etc/os-release | grep '^ID=' | awk -F=  '{ print $2 }'`
			os_pseudo=`cat /etc/os-release | grep '^VERSION_CODENAME=' | awk -F=  '{ print $2 }'`
			os_rev=`cat /etc/os-release | grep '^VERSION_ID=' | awk -F=  '{ print $2 }'`
		else
			os_dist=`cat /etc/lsb-release | grep '^DISTRIB_ID' | awk -F=  '{ print $2 }'`
			os_pseudo=`cat /etc/lsb-release | grep '^DISTRIB_CODENAME' | awk -F=  '{ print $2 }'`
			os_rev=`cat /etc/lsb-release | grep '^DISTRIB_RELEASE' | awk -F=  '{ print $2 }'`
		fi
	fi
}

function version_gt() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" == "$1"; }

validate_python_installed() {
	python_installed=`command -v $1 -V >/dev/null && echo True || echo False`
}

validate_python_binary() {
	is_python_binary_by_user_valid=`command $python_binary_path -c 'print("True");' 2>/dev/null`
	if [[ $is_python_binary_by_user_valid = "True" ]]; then
		return "True"
	else
		return "False"
	fi
}

validate_python_version () {
	python_version_raw=`$python_binary_path -V 2>&1`
	python_version=`echo $python_version_raw | cut -d " " -f 2`
	python_major_version=`echo $python_version_raw | cut -d " " -f 2 | cut -d "." -f 1,2`
}

get_python_path() {
	exit_loop="False"
	while [ $exit_loop = "False" ];
	do
		read python_binary_path
		
		if [[ $python_binary_path == "i" || $python_binary_path == "I" ]]; then
		
			install_dev_essentials
		
			wget -O /tmp/python3.tar.gz $python3_tarball &>> install_syntraf.log
			tar -xvzf /tmp/python3.tar.gz -C /tmp &>> install_syntraf.log
			cd /tmp/Python-3.10.6
			./configure --prefix=${base_dir_for_packages}/python3 &>> install_syntraf.log
			if [[ $? -eq 0 ]]; then
				make &>> install_syntraf.log
				if [[ $? -eq 0 ]]; then
					make install  &>> install_syntraf.log
					if [[ $? -eq 0 ]]; then
						/usr/bin/printf "$green\xE2\x9C\x94 Python3 version 3.10.6 successfully installed.\n$clear"
						python_binary_path="${base_dir_for_packages}/python3/bin/python3"
						python_installed="True"
						exit_loop="True"
					else
						/usr/bin/printf "${red}An error occured while installing python3, see install_syntraf.log for details.${clear}\n"
						exit
					fi
				else
					/usr/bin/printf "${red}An error occured while installing python3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
			else
				/usr/bin/printf "${red}An error occured while installing python3, see install_syntraf.log for details.${clear}\n"
				exit
			fi
		elif [[ ! -f $python_binary_path ]]; then
			printf "${yellow}This path is invalid, please provide a path to a valid python binary or press ctrl+c to abort : ${clear}"
		else
			exit_loop="True"
		fi
	done
}

check_python() {
	python_ok="False"
	python_binary_path=`command -v python3`
	regex='^[0-9]+.[0-9]+$'
	
	while [ $python_ok = "False" ];
	do
		validate_python_installed
		if [[ $python_installed == "True" ]]; then
			validate_python_version

			if [[ $python_major_version =~ $regex ]]; then
				if version_gt $python_min_req_version $python_major_version; then
					/usr/bin/printf "${green}\xE2\x9C\x94 Python version $python_version was found and satisfied the minimum requirement of version $python_min_req_version\n${clear}"
					python_ok="True"
				else
					/usr/bin/printf "${yellow}Python version $python_version was found but does not satisfy the minimum requirement of version $python_min_req_version\n${clear}"
					/usr/bin/printf "Please provide the path of a valid python binary or enter ${cyan}[i]${clear} to install : "
					get_python_path
				fi
			else
				echo "a"
			fi
		else
			/usr/bin/printf "${yellow}The path provided does not point to a valid python binary.\n${clear}"
			echo -n "Please provide a path to a valid python binary or press ctrl+c to abort : "
			get_python_path
		fi
	done
}

get_pip_path() {
	exit_loop="False"
	
	while [ $exit_loop = "False" ];
	do
		read pip_binary_path
		if [[ $pip_binary_path == "i" || $pip_binary_path == "I" ]]; then
			if [[ "$os_distroBasedOn" == "RedHat" ]]; then
				yum -y install python3-pip &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing pip3, see install_syntraf.log for details.${clear}\n"
					exit
				fi			
			elif [[ "$os_distroBasedOn" == "Debian" ]]; then
				export DEBIAN_FRONTEND=noninteractive &>> install_syntraf.log
				apt-get --yes install python3-pip &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing pip3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
			fi
		elif [[ $pip_binary_path = "" ]]; then
			pip_binary_path=pip3
			exit_loop="True"
		else
			exit_loop="True"
		fi
	done
}

check_pip() {
	python_modules=`command $python_binary_path -c 'help("modules");' 2>/dev/null`
	#pip_exist=`echo $python_modules | grep " pip " | wc -l`
	pip_exist=
	if [ -n "$pip_exist" ]; then
		echo "PIP exist"
	fi
	
	pip_ok="False"
	while [ $pip_ok = "False" ];
	do
		pip_installed=`command -v $pip_binary_path >/dev/null && echo True || echo False`

		if [[ $pip_installed = "True" ]]; then
			version_raw=$($pip_binary_path -V 2>&1 | grep -Po '.+(?= +from\b)')
			version=`echo $version_raw | cut -d " " -f 2`
			/usr/bin/printf "$green\xE2\x9C\x94 Python Package Index (pip) version $version found.\n$clear"
			pip_ok="True"
		else
			/usr/bin/printf "${yellow}Python Package Index (pip) was not found, please provide a path to a valid pip3 binary or enter ${cyan}[i]${yellow} to install : $clear"
			get_pip_path
		fi
	done
}

client_or_server() {
	valid_answer="False"
	while [ $valid_answer = "False" ]; 
	do
		/usr/bin/printf "Do you want to install a SYNTRAF client ${cyan}[c]${clear}, server ${cyan}[s]${clear}, or both ${cyan}[b]${clear}? : "
		read client_or_server
		regex='^[CcBbsS]$'
		if [[ $client_or_server =~ $regex ]]; then
			valid_answer="True"
		else
			/usr/bin/printf "${yellow}'$client_or_server' is not a valid option.\n${clear}"
		fi
	done
}

setup_syntraf_root() {
	valid_answer="False"
	while [ $valid_answer = "False" ]; 
	do
		valid_answer2="False"
		echo -n "Please provide the full path where you want to install SYNTRAF or press enter to use the default (${default_syntraf_install_dir}) : "
		read syntraf_install_dir

		if [[ $syntraf_install_dir == "" ]]; then
			syntraf_install_dir="${default_syntraf_install_dir}"
		fi
		
		# Add the trailing slash to make sure we deal with a directory
		if [[ ${syntraf_install_dir: -1} != "/" ]]; then
			syntraf_install_dir="$syntraf_install_dir/"
		fi
	
		# Make sure the format of the path is valid
		if [[ $syntraf_install_dir =~ ^\/.+(\/.+)+ ]]; then
			if [[ -d "$syntraf_install_dir" ]]
			then
				/usr/bin/printf "${yellow}Directory '$syntraf_install_dir' already exist on your filesystem, overwrite? ${cyan}[y/n]${clear} : "
				
				while [ $valid_answer2 = "False" ]; 
				do
					read overwrite_confirmation
					regex='^[YyNn]$'
					if [[ $overwrite_confirmation =~ $regex ]]; then
						valid_answer2="True"
					else
						/usr/bin/printf "${yellow}'${overwrite_confirmation}' is an invalid answer.\n${clear}"
					fi
				done
				
				if [[ $overwrite_confirmation == "y" || $overwrite_confirmation == "Y" ]]; then
					rm -rf $syntraf_install_dir
					valid_answer="True"
				else
					/usr/bin/printf "${red}Script aborted by user.\n${clear}"
					exit
				fi
			else
				valid_answer="True"
			fi
		else
			/usr/bin/printf "${yellow}The path '$syntraf_install_dir' is invalid.\n${clear}"
		fi
	done
}

create_python_env () {

	if [[ "$os_distroBasedOn" == "Debian" ]]; then
		export DEBIAN_FRONTEND=noninteractive &>> install_syntraf.log
		apt-get --yes install python3-venv  &>> install_syntraf.log
		if [[ $? -ne 0 ]]; then
			/usr/bin/printf "${red}An error occured while installing prerequisites for Python virtual environment, see install_syntraf.log for details.${clear}\n"
			exit
		fi
	fi


	$python_binary_path -m venv $base_dir_for_packages/$python_env_dir &>> install_syntraf.log
	
	
	if [[ $? -ne 0 ]]; then
		/usr/bin/printf "${red}Creation of the Python virtual environement failed.\n${clear}"
		exit
	fi
	source $base_dir_for_packages/$python_env_dir/bin/activate &>> install_syntraf.log
	if [[ $? -ne 0 ]]; then
		/usr/bin/printf "${red}Activation of the Python virtual environement failed.\n${clear}"
		exit
	fi

}

install_python_packages() {
	
	${base_dir_for_packages}/$python_env_dir/bin/pip3 install wheel &>> install_syntraf.log
	
	if [[ $client_or_server == "C" || $client_or_server == "c" ]]; then
		${base_dir_for_packages}/$python_env_dir/bin/pip3 install -r $syntraf_install_dir/requirements_client.txt &>> install_syntraf.log
	elif [[ $client_or_server == "S" || $client_or_server == "s" ]]; then
		${base_dir_for_packages}/$python_env_dir/bin/pip3 install -r $syntraf_install_dir/requirements_server.txt &>> install_syntraf.log
	elif [[ $client_or_server == "B" || $client_or_server == "b" ]]; then
		${base_dir_for_packages}/$python_env_dir/bin/pip3 install -r $syntraf_install_dir/requirements_server.txt &>> install_syntraf.log
	fi

	if [[ $? -eq 0 ]]; then
		/usr/bin/printf "$green\xE2\x9C\x94 Python modules installation completed.\n$clear"
		rm -rf $syntraf_install_dir/requirements_server.txt
		rm -rf $syntraf_install_dir/requirements_client.txt
	else
		/usr/bin/printf "${red}An error occured while installing python modules, see install_syntraf.log for details.${clear}\n"
		exit
	fi

}

update_pip() {
	${base_dir_for_packages}/$python_env_dir/bin/python3 -m pip install --upgrade pip &>> install_syntraf.log
}

download_syntraf() {
	wget -O /tmp/syntraf.tar.gz $syntraf_tarball &>> install_syntraf.log
	
	if [[ $? -eq 0 ]]; then
		/usr/bin/printf "$green\xE2\x9C\x94 SYNTRAF download completed.\n$clear"
	else
		/usr/bin/printf "${red}An error occured while downloading SYNTRAF, see install_syntraf.log for details.${clear}\n"
		exit
	fi
	
	tar -xvzf /tmp/syntraf.tar.gz -C /tmp/ &>> install_syntraf.log
	
	if [[ $? -eq 0 ]]; then
		/usr/bin/printf "$green\xE2\x9C\x94 SYNTRAF extraction completed.\n$clear"
	else
		/usr/bin/printf "${red}An error occured while extracting SYNTRAF, see install_syntraf.log for details.${clear}\n"
		exit
	fi
	
	mkdir -p $syntraf_install_dir
	
	if [[ $? -eq 0 ]]; then
		/usr/bin/printf "$green\xE2\x9C\x94 SYNTRAF directory created.\n$clear"
	else
		/usr/bin/printf "${red}An error occured while creating SYNTRAF directory, see install_syntraf.log for details.${clear}\n"
		exit
	fi
	
	mv /tmp/syntraf-latest/* $syntraf_install_dir
	
	if [[ $? -eq 0 ]]; then
		/usr/bin/printf "$green\xE2\x9C\x94 SYNTRAF files installed in ${syntraf_install_dir}.\n$clear"
	else
		/usr/bin/printf "${red}An error occured while installing SYNTRAF files in ${syntraf_install_dir}, see install_syntraf.log for details.${clear}\n"
		exit
	fi
	
	rm -rf /tmp/syntraf-latest/
	rm -rf /tmp/syntraf.tar.gz
}

install_dev_essentials() {
			if [[ "$os_distroBasedOn" == "RedHat" ]]; then
				yum -y groupinstall "Development Tools" &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing prerequisites for iperf3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
				yum -y install openssl-devel &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing prerequisites for iperf3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
				
			elif [[ "$os_distroBasedOn" == "Debian" ]]; then
				export DEBIAN_FRONTEND=noninteractive &>> install_syntraf.log
				apt-get --yes install build-essential  &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing prerequisites for iperf3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
				apt-get --yes install libssl-dev libtool &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing prerequisites for iperf3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
			fi
}

get_iperf3_path() {
	exit_loop="False"
	
	while [ $exit_loop = "False" ];
	do
		read IPERF3_BINARY_PATH
		if [[ $IPERF3_BINARY_PATH == "i" || $IPERF3_BINARY_PATH == "I" ]]; then
		
			install_dev_essentials
		
			wget -O /tmp/iperf3.tar.gz $iperf3_tarball &>> install_syntraf.log
			tar -xvzf /tmp/iperf3.tar.gz -C /tmp &>> install_syntraf.log
			cd /tmp/iperf-3.11
			./configure --prefix=${base_dir_for_packages}/iperf3 &>> install_syntraf.log
			if [[ $? -eq 0 ]]; then
				make &>> install_syntraf.log
				if [[ $? -eq 0 ]]; then
					make install  &>> install_syntraf.log
					if [[ $? -eq 0 ]]; then
						IPERF3_BINARY_PATH="${base_dir_for_packages}/iperf3/iperf3"
						/usr/bin/printf "$green\xE2\x9C\x94 Iperf3 version 3.11 successfully installed in '${IPERF3_BINARY_PATH}'.\n$clear"
						iperf3_installed="True"
						exit_loop="True"
					else
						/usr/bin/printf "${red}An error occured while installing iperf3, see install_syntraf.log for details.${clear}\n"
						exit
					fi
				else
					/usr/bin/printf "${red}An error occured while installing iperf3, see install_syntraf.log for details.${clear}\n"
					exit
				fi
			else
				/usr/bin/printf "${red}An error occured while installing iperf3, see install_syntraf.log for details.${clear}\n"
				exit
			fi
		else
			if [[ ! -f $IPERF3_BINARY_PATH ]]; then
				/usr/bin/printf "${yellow}This path is invalid, please provide a path to a valid iperf3 binary or ${cyan}[i] ${yellow}to install ${clear}: "
				iperf3_installed="False"
			else
				exit_loop="True"
			fi
		fi
	done
}

check_iperf3() {
	iperf3_ok="False"
	iperf3_installed=`command -v $IPERF3_BINARY_PATH >/dev/null && echo True || echo False`
	
	while [ $iperf3_ok = "False" ];
	do
		if [[ $iperf3_installed = "True" ]]; then
			iperf3_version_raw=$($IPERF3_BINARY_PATH -v 2>&1 | grep -Po 'iperf (\d.\d+)')
			iperf3_detected_version=`echo $iperf3_version_raw | cut -d " " -f 2`
			
			if version_gt $iperf3_min_req_version $iperf3_detected_version; then
				/usr/bin/printf "${green}\xE2\x9C\x94 iperf3 version $iperf3_detected_version was found and satisfied the minimum requirement of version $iperf3_min_req_version\n${clear}"
				iperf3_ok="True"
			else
				/usr/bin/printf "${yellow}iperf3 version $iperf3_detected_version was found but does not satisfy the minimum requirement of version $iperf3_min_req_version\n${clear}"
				/usr/bin/printf "${yellow}Please provide the path of a valid iperf3 binary or ${cyan}[i]${yellow} to install ${clear}: "
				get_iperf3_path
			fi

		else
			/usr/bin/printf "${yellow}iperf3 was not found, please provide a path to a valid iperf3 binary or ${cyan}[i]${yellow} to install${clear} : "
			get_iperf3_path
		fi
	done
}

save_config_global() {
	
	if [ -f /etc/syntraf.conf ] ; then
		regex='^[aAcC]$'
		exit_loop="False"
		while [ $exit_loop = "False" ];
		do
			/usr/bin/printf "${yellow}Generating config file; '/etc/syntraf.conf' already exist, ${cyan}a${clear}${yellow}bort or backup and ${cyan}c${clear}${yellow}ontinue? [a/c] : ${clear}"
			read answer
			if [[ $answer =~ $regex ]]; then
				exit_loop="True"
			else
				/usr/bin/printf "${yellow} '$answer' is not a valid option. \n${clear}"
			fi
		done
	fi
	
	if [[ $answer == "a" || $answer == "A"  ]]; then
		/usr/bin/printf "${red}Script aborted by user.\n${clear}"
		exit
	fi
	
	datetime=`date "+%Y%m%d_%H%M"`
	mv /etc/syntraf.conf /etc/syntraf.conf.bk.${datetime}
				
	curr_datetime=`date`
	echo "#CONFIG GENERATED BY SYNTRAF INSTALL SCRIPT ON ${curr_datetime}" > /etc/syntraf.conf
	echo "" >> /etc/syntraf.conf
	echo "[GLOBAL]" >> /etc/syntraf.conf
	
	if [[ $client_or_server == "C" || $client_or_server == "c" || $client_or_server == "b" || $client_or_server == "B" ]]; then
		echo "IPERF3_BINARY_PATH = \"${IPERF3_BINARY_PATH}\"" >> /etc/syntraf.conf
	elif [[ $client_or_server == "s" || $client_or_server == "S" ]]; then
		echo "IPERF3_BINARY_PATH = \"DISABLED\"" >> /etc/syntraf.conf
	fi
	
	echo "IPERF3_TIME_SKEW_THRESHOLD = \"300\"" >> /etc/syntraf.conf
	echo "LOG_TO = \"file\"" >> /etc/syntraf.conf 
	echo "LOG_LEVEL = \"INFO\"" >> /etc/syntraf.conf 
	echo "LOG_MAX_SIZE_PER_FILE_MB = \"2\"" >> /etc/syntraf.conf
	echo "LOG_FILE_TO_KEEP = \"3\"" >> /etc/syntraf.conf
	echo "WATCHDOG_CHECK_RATE = \"2\"" >> /etc/syntraf.conf
	echo "" >> /etc/syntraf.conf
}

save_config_client() {
	is_client_uid_ok="False"
	regex_client_uid='^[A-Za-z0-9_-]+$'
	is_server_ip_ok="False"
	regex_ip=''
	
	while [ $is_client_uid_ok = "False" ];
	do
		echo -n "Please enter this machine unique ID : "
		read CLIENT_UID
		if [[ $CLIENT_UID =~ $regex_client_uid ]]; then
			is_client_uid_ok="True"
		else
			/usr/bin/printf "${yellow} '$answer' is not a valid option. \n${clear}"
		fi
	done
	
	if [[ $client_or_server == "B" || $client_or_server == "b" || $client_or_server == "S" || $client_or_server == "s" ]]; then
		SERVER_IP="127.0.0.1"
		TOKEN=${random_token}
	else
		while [ $is_server_ip_ok = "False" ];
		do
			echo -n "Please enter the server ip address : "
			read SERVER
			if [[ $SERVER =~ $regex_ip ]]; then
				is_server_ip_ok="True"
			else
				/usr/bin/printf "${yellow} '$answer' is not a valid option. \n${clear}"
			fi
		done	

		echo -n "Please enter the token : "
		read TOKEN
	fi
	
	echo "[CLIENT]" >> /etc/syntraf.conf
	echo "CLIENT_UID = \"${CLIENT_UID}\"" >> /etc/syntraf.conf
	echo "SERVER = \"${SERVER_IP}\"" >> /etc/syntraf.conf
	echo "TOKEN = \"${TOKEN}\"" >> /etc/syntraf.conf
	echo "" >> /etc/syntraf.conf
}

save_config_server() {
	echo "[SERVER]" >> /etc/syntraf.conf
	echo "BIND_ADDRESS = \"0.0.0.0\"" >> /etc/syntraf.conf
	echo "" >> /etc/syntraf.conf
	
	echo "[SERVER.TOKEN]" >> /etc/syntraf.conf
	echo "DEFAULT = \"${random_token}\"" >> /etc/syntraf.conf
	echo "" >> /etc/syntraf.conf
}

save_config_mesh_group() {
	echo "[[MESH_GROUP]]" >> /etc/syntraf.conf
	echo "UID = \"DEFAULT_MG_VOIP\"" >> /etc/syntraf.conf 
	echo "BANDWIDTH = \"87.2K\"" >> /etc/syntraf.conf
	echo "DSCP = \"46\"" >> /etc/syntraf.conf
	echo "PACKET_SIZE = \"218\"" >> /etc/syntraf.conf
	echo "INTERVAL = \"1\"" >> /etc/syntraf.conf
	echo "" >> /etc/syntraf.conf

}

ctrlc() {
	/usr/bin/printf "\n${yellow}Ctrl+c detected, are you sure you want to exit the installation? ${cyan}[y/n]${clear} : "

	while [ $valid_answer = "False" ]; 
	do
		read exit_confirmation
		regex='^[YyNn]$'
		if [[ $exit_confirmation =~ $regex ]]; then
			valid_answer="True"
		else
			/usr/bin/printf "${yellow}'${exit_confirmation}' is an invalid answer.\n${clear}"
		fi
	done

	if [[ $exit_confirmation == "y" || $exit_confirmation == "Y" ]]; then
		/usr/bin/printf "${red}Script aborted by user.\n${clear}"
		exit
	fi
}

check_git () {
	git_ok="False"
	while [ $git_ok = "False" ];
	do
		git_installed=`command -v $git_binary_path >/dev/null && echo True || echo False`
		
		if [[ $git_binary_path = "" || ! -f $git_binary_path || $git_installed = "False" ]]; then
			/usr/bin/printf "${yellow}git was not found or is invalid, please provide a path to a valid git binary or ${cyan}[i]${yellow} to install${clear} : "
			get_git_path
		else
			git_ok="True"
		fi
	done
}

get_git_path() {
	exit_loop="False"
	
	while [ $exit_loop = "False" ];
	do
		read git_binary_path
		if [[ $git_binary_path == "i" || $git_binary_path == "I" ]]; then
			if [[ "$os_distroBasedOn" == "RedHat" ]]; then
				yum -y install git &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing git, see install_syntraf.log for details.${clear}\n"
					exit
				else
					/usr/bin/printf "$green\xE2\x9C\x94 Git successfully installed.\n$clear"
					git_binary_path=`command -v git`
					exit_loop="True"
				fi
				
			elif [[ "$os_distroBasedOn" == "Debian" ]]; then
				export DEBIAN_FRONTEND=noninteractive &>> install_syntraf.log
				apt-get --yes install git  &>> install_syntraf.log
				if [[ $? -ne 0 ]]; then
					/usr/bin/printf "${red}An error occured while installing git, see install_syntraf.log for details.${clear}\n"
					exit
				else
					/usr/bin/printf "$green\xE2\x9C\x94 Git successfully installed.\n$clear"
					git_binary_path=`command -v git`
					exit_loop="True"
				fi
			fi
		else
			if [[ ! -f $git_binary_path ]]; then
				/usr/bin/printf "${yellow}This path is invalid, please provide a path to a valid git binary or ${cyan}[i] ${yellow}to install ${clear}: "
			else
				exit_loop="True"
			fi
		fi
	done
}

client_only_param() {
	sed -i 's/client_only = False/client_only = True/g' st_global.py &>> install_syntraf.log
	
	if [[ $? -ne 0 ]]; then
		/usr/bin/printf "${red}An error occured while modifying st_global.py, see install_syntraf.log for details.${clear}\n"
		exit
	else
		/usr/bin/printf "$green\xE2\x9C\x94 This is a client only, st_global.py modified (client_only = True) to reduce the amount of modules required.\n$clear"
	fi
}


#############
### START ###
#############
clear
echo "Beginning installation" &> install_syntraf.log
#trap ctrlc SIGINT
display_banner
check_if_root
detect_os

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
	if [[ "$os_distroBasedOn" == "RedHat" || "$os_distroBasedOn" == "Debian" ]]; then
		/usr/bin/printf "${green}\xE2\x9C\x94 $os_dist $os_pseudo $os_rev based on $os_distroBasedOn\n${clear}"
		
		# Ask the user if this is a SYNTRAF server, a client or both
		client_or_server
				
		# Acquired the install path and deal with existing directory
		setup_syntraf_root
		
		check_git
		download_syntraf
				
		# Make sure we have python installed
		check_python
						
		# Create the python environement
		# Require the syntraf directoy to exist
		create_python_env
		
		# Make sure we have pip installed
		# require the python env
		check_pip
		update_pip
		install_python_packages
		
		save_config_global
		/usr/bin/printf "${green}\xE2\x9C\x94 Global config generated.\n${clear}"
		
		if [[ $client_or_server == "B" || $client_or_server == "b" ]]; then
			check_iperf3
			save_config_server
			/usr/bin/printf "${green}\xE2\x9C\x94 Server config generated.\n${clear}"

			save_config_client
			/usr/bin/printf "${green}\xE2\x9C\x94 Client config generated.\n${clear}"
			
			save_config_mesh_group
			/usr/bin/printf "${green}\xE2\x9C\x94 Default mesh group config generated.\n${clear}"
		
		elif [[ $client_or_server == "C" || $client_or_server == "c" ]]; then
			check_iperf3
			save_config_client
			client_only_param
			/usr/bin/printf "${green}\xE2\x9C\x94 Client config generated.\n${clear}"
			
		elif [[ $client_or_server == "S" || $client_or_server == "s" ]]; then
			save_config_server
			/usr/bin/printf "${green}\xE2\x9C\x94 Server config generated.\n${clear}"
			save_config_mesh_group
			/usr/bin/printf "${green}\xE2\x9C\x94 Default mesh group config generated.\n${clear}"
			#grafana
			#influxdb
		fi

	else
		/usr/bin/printf "${red}This installation script does not support your operating system or os_distribution.${clear}"
	fi
else
	/usr/bin/printf "${red}This installation script does not support your operating system.${clear}"
	exit
fi