#!/bin/bash
DMARC_CONF=/etc/dmarc-parser/config.ini
DMARC_BIN=/opt/dmarc-parser.py
RECIPIENTS="bob@example.net alice@example.com"
TMP=$(mktemp)
for recipient in $RECIPIENTS; do
  echo "To: $recipient" >> $TMP
done
echo -e "Subject: Dmarc Report for $(date -d @$(($(date +%s) - 86400)) +%Y-%m-%d)">> $TMP
echo -e "\nGraphite dashboard: http://graphite.colo.lair/dashboard/#DMARC%20Graphs" >> $TMP
echo -e "Last 3 weeks: http://graphite.colo.lair/dashboard/#DMARC%20Graphs%20(Last%203%20Weeks)\n\n" >> $TMP
$DMARC_BIN -c $DMARC_CONF --imap >> $TMP
cat $TMP|/usr/sbin/sendmail -t
rm $TMP
