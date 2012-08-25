PPSLdapAuth (0.1.2) should provide authentication from LDAP-Servers like OpenLDAP, MS Active Directory and others. Please uninstall prior version before upgrade to a new Version. Configured Values will not be lost, the are stored permanently in the Database, but you have to reenable PPSLdapAuth after again.

NEW in 0.1.2: Added new view im Memberlist where only Members with more than zero posts are listen.

NEW in 0.1.1: Added Synchronisation of LDAP-Email Addresses into SMF (See Administration -> Members -> Synchronisation)

If PPSLdapAuth is enabled, the users cannot change their password, secret question and answer, email address and username.

This Modification was created especially for the PirateParty Switzerland in July 2011 for a migration from phphBB to SMF-2. It is based on an verry old LdapAuth module found in the simplemachines.org Forum.

In the Administration you should find a new tab inside "Features and Options" with the PPSLdapAuth Settings. Check them carfully, not all Options are needed and some are ignored if you have filld out others.

Existing Users in the SMF-Databse will still be able to login after this Modification is installed. If you only want LDAP-Authorisation, you should disable the SMF-Registration under Registration->Settings->"Method of registration employed for new members" and use an other Script which inserts users into the LDAP.

If you don't want to store LDAP-Users in the SMF-Database - so they are able to login after you uninstall this Modification, you should uncheck "Store LDAP Password".

greets, LukyLuke <l.zurschmiede@delightsoftware.com>