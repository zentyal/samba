Samba3-ByExample-images-html = images/Charity-Network.png images/AccountingNetwork.png images/acct2net.png images/chap4-net.png images/chap5-net.png images/UNIX-Samba-and-LDAP.png images/chap6-net.png images/XP-screen001.png images/chap7-idresol.png images/ch7-singleLDAP.png images/ch7-fail-overLDAP.png images/ch7-dual-additive-LDAP.png images/ch7-dual-additive-LDAP-Ok.png images/chap7-net-Ar.png images/chap7-net2-Br.png images/openmag.png images/chap9-SambaDC.png images/chap9-ADSDC.png images/ch8-migration.png images/UserMgrNT4.png images/wxpp001.png images/wxpp004.png images/wxpp006.png images/wxpp007.png images/wxpp008.png images/lam-login.png images/lam-config.png images/lam-users.png images/lam-groups.png images/lam-group-members.png images/lam-hosts.png images/imc-usermanager2.png images/WINREPRESSME-Capture.png images/WINREPRESSME-Capture2.png images/HostAnnouncment.png images/NullConnect.png images/UserConnect.png images/WindowsXP-NullConnection.png images/WindowsXP-UserConnection.png 
Samba3-ByExample-images-latex = Samba3-ByExample/images/Charity-Network Samba3-ByExample/images/AccountingNetwork Samba3-ByExample/images/acct2net Samba3-ByExample/images/chap4-net Samba3-ByExample/images/chap5-net Samba3-ByExample/images/UNIX-Samba-and-LDAP Samba3-ByExample/images/chap6-net Samba3-ByExample/images/XP-screen001 Samba3-ByExample/images/chap7-idresol Samba3-ByExample/images/ch7-singleLDAP Samba3-ByExample/images/ch7-fail-overLDAP Samba3-ByExample/images/ch7-dual-additive-LDAP Samba3-ByExample/images/ch7-dual-additive-LDAP-Ok Samba3-ByExample/images/chap7-net-Ar Samba3-ByExample/images/chap7-net2-Br Samba3-ByExample/images/openmag Samba3-ByExample/images/chap9-SambaDC Samba3-ByExample/images/chap9-ADSDC Samba3-ByExample/images/ch8-migration Samba3-ByExample/images/UserMgrNT4 Samba3-ByExample/images/wxpp001 Samba3-ByExample/images/wxpp004 Samba3-ByExample/images/wxpp006 Samba3-ByExample/images/wxpp007 Samba3-ByExample/images/wxpp008 Samba3-ByExample/images/lam-login Samba3-ByExample/images/lam-config Samba3-ByExample/images/lam-users Samba3-ByExample/images/lam-groups Samba3-ByExample/images/lam-group-members Samba3-ByExample/images/lam-hosts Samba3-ByExample/images/imc-usermanager2 Samba3-ByExample/images/WINREPRESSME-Capture Samba3-ByExample/images/WINREPRESSME-Capture2 Samba3-ByExample/images/HostAnnouncment Samba3-ByExample/images/NullConnect Samba3-ByExample/images/UserConnect Samba3-ByExample/images/WindowsXP-NullConnection Samba3-ByExample/images/WindowsXP-UserConnection 
Samba3-ByExample-images- = 
Samba3-ByExample-txt-chunks: output/textdocs/Samba3-ByExample/index.txt output/textdocs/Samba3-ByExample/preface.txt output/textdocs/Samba3-ByExample/simple.txt output/textdocs/Samba3-ByExample/small.txt output/textdocs/Samba3-ByExample/secure.txt output/textdocs/Samba3-ByExample/Big500users.txt output/textdocs/Samba3-ByExample/happy.txt output/textdocs/Samba3-ByExample/2000users.txt output/textdocs/Samba3-ByExample/unixclients.txt output/textdocs/Samba3-ByExample/upgrades.txt output/textdocs/Samba3-ByExample/ntmigration.txt output/textdocs/Samba3-ByExample/nw4migration.txt output/textdocs/Samba3-ByExample/kerberos.txt output/textdocs/Samba3-ByExample/DomApps.txt output/textdocs/Samba3-ByExample/HA.txt output/textdocs/Samba3-ByExample/appendix.txt output/textdocs/Samba3-ByExample/primer.txt 
Samba3-ByExample-images-latex-svg = $(wildcard $(addsuffix .svg, $(Samba3-ByExample-images-latex)))
Samba3-ByExample-images-latex-eps: $(addsuffix .eps, $(Samba3-ByExample-images-latex))
Samba3-ByExample-images-latex-pdf: $(patsubst %.svg, %.pdf, $(Samba3-ByExample-images-latex-svg))
Samba3-ByExample-images-latex-png: $(filter-out $(patsubst %.svg,%.png,$(Samba3-ByExample-images-latex-svg)), $(addsuffix .png, $(Samba3-ByExample-images-latex)))

$(HTMLDIR)/%: Samba3-ByExample/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLDIR)/Samba3-ByExample/%: Samba3-ByExample/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLHELPDIR)/Samba3-ByExample/%: Samba3-ByExample/%
	@mkdir -p $(@D)
	@cp $< $@

Samba3-ByExample-images-html-single: $(addprefix $(HTMLDIR)/, $(Samba3-ByExample-images-html))
Samba3-ByExample-images-html-chunks: $(addprefix $(HTMLDIR)/Samba3-ByExample/, $(Samba3-ByExample-images-html))
Samba3-ByExample-images-htmlhelp: $(addprefix $(HTMLHELPDIR)/Samba3-ByExample/, $(Samba3-ByExample-images-html))
