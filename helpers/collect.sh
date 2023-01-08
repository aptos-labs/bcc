for i in `seq 0 7`; do
	echo  "bcc ./profile.py -f -p $PID -F 100 -a --stack-storage-size 2097152 3 > /tmp/profile.folded_$i"
	sudo python3 ./profile.py -f -p $PID -F 100 -a --stack-storage-size 2097152 3 > /tmp/profile.folded_$i
	echo "bcc ./offcputime.py -f -p $PID --stack-storage-size 2097152 3 > /tmp/offcpu.folded_$i"
	sudo python3 ./offcputime.py -f -p $PID --stack-storage-size 2097152 3 > /tmp/offcpu.folded_$i
done
