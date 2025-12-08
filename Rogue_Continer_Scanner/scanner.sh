#!/bin/bash

echo "🔍 Starting Container Scan..."
echo "--------------------------------------"

for container_id in $(docker ps -q); do
	
	#display name
	name=$(docker inspect --format '{{.Name}}' $container_id | sed 's/\///')

	user=$(docker inspect --format '{{.Config.User}}' $container_id)

	if [ -z "$user" ] || [ "$user" == "0" ] || [ "$user" == "root" ]; then
        	echo "❌ [RISK DETECTED] Container '$name' is running as ROOT!"
    	else
        	echo "✅ [SECURE] Container '$name' is running as User: $user"
    	fi
done

echo "--------------------------------------"
echo "Scan Complete."
