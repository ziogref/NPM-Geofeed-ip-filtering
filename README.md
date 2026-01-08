# NPM-Geofeed-ip-filtering
gathering data from Geofeed files (RFC8805) for various Internet providers, applying regional filtering and adding those into Nginx Proxy Managers Allow list for access restriction. Script runs from any device that has Python that interacts with NPMs API.

My configuration in Unraid.

Setup, place the ```npm_secrets.json``` file in ```/boot/config/``` in unraid. 
```http://[unraidiphere]/Main/Browse?dir=/boot%2Fconfig```

Open the file and change the values for your NPM instance. 

Install ```Python 3 for Unraid``` and ```user scripts``` from the community app store.

Add contents from ```pip installs``` to a new script and set that to run on ```at Startup of Array```

Add contents of ```NPMAccessList.py``` to a new script and set that to run on what ever schedule you would like
