#!/bin/bash

for server in `cat ./server/192.168.100.0.txt`; do
	echo "########################### $server ###########################"	
	nonrootmounts=$(/usr/sbin/showmount -e $server|grep -v Export|awk '{print substr($1,2)}'|xargs)
	mounts="root $nonrootmounts"
	echo $mounts	
	for mntdir in $mounts; do
	    ret=$(mountpoint -q -d /mnt/spider/$mntdir)
	    echo "Unmounting /mnt/spider/$mntdir..."
	    while [ ${ret:0:1} -eq 0 ]
	    do
		umount /mnt/spider/$mntdir
                ret=$(mountpoint -q -d /mnt/spider/$mntdir)
		echo -ne "Trying unmount: [#.....................................................] (0/100%) \r"
	    done
		echo "Trying unmount: [######################################################] (100/100%)"
                DIR="root"
                if [ $mntdir == $DIR ]
                then
                        mount $server:/ /mnt/spider/root
                else
                        mount $server:/$mntdir /mnt/spider/$mntdir
                fi
		if [ -d /mnt/spider/$mntdir ]
		then
			sleep 1
		else
			mkdir /mnt/spider/$mntdir
		fi
                ret=$(mountpoint -q -d /mnt/spider/$mntdir)
                if [[ ${ret:0:1} -eq 0 ]];
                then
                    echo "$server Mounted successfully at /mnt/spider/$mntdir"
                else
                    echo "/mnt/spider/$mntdir mount failed... Quiting!"
                fi
        done

	echo "Modifying config file..."
	sed -i.bak -e '/logpath/d' /home/spider/spider.conf
	sed -i.bak -e '/hostip/d' /home/spider/spider.conf
	echo 'logpath /log/spider/'$server'.log' >> /home/spider/spider.conf
	echo 'hostip '$server >> /home/spider/spider.conf
	echo "Done!"
	echo "Creating log file..."
	touch /log/spider/$server.log
	echo "Done!"
	echo "Starting scan..."	
	time env LD_LIBRARY_PATH=/usr/lib ./spider
	echo "Scan completed!"
	echo "See results in /log/spider/$server.log"
	echo "Removing mounts...."

	nonrootunmounts=$(df -ah|awk 'match($1,":/"){print substr($1,RSTART+2)}'|xargs)
	unmounts="root $nonrootmounts"
	for unmountpoints in $unmounts; do
	    ret=$(mountpoint -q -d /mnt/spider/$unmountpoints)
            echo "Unmounting /mnt/spider/$unmountpoints..."
            while [ ${ret:0:1} -eq 0 ]
            do
                umount /mnt/spider/$unmountpoints
                ret=$(mountpoint -q -d /mnt/spider/$unmountpoints)
                echo -ne "Trying unmount: [#.....................................................] (0/100%) \r"
            done
                echo "Trying unmount: [######################################################] (100/100%)"
	done
	echo "#####################################################################"	
	sleep 5
done
