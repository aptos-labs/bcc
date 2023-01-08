cat /tmp/profile.folded_*|perl -e 'while (<>) { s/^([\w-]+)[-_]\d*;/$1;/;printf"$_";}' > /tmp/profile.folded
cat /tmp/offcpu.folded_*|perl -e 'while (<>) { s/^([\w-]+)[-_]\d*;/$1;/;printf"$_";}' > /tmp/offcpu.folded
