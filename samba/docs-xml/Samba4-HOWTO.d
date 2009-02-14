Samba4-HOWTO-images- = 
Samba4-HOWTO-txt-chunks: output/textdocs/Samba4-HOWTO/index.txt output/textdocs/Samba4-HOWTO/protocol.txt output/textdocs/Samba4-HOWTO/samba.txt output/textdocs/Samba4-HOWTO/config.txt output/textdocs/Samba4-HOWTO/ldb.txt output/textdocs/Samba4-HOWTO/security=share.txt output/textdocs/Samba4-HOWTO/security=user.txt output/textdocs/Samba4-HOWTO/domain-pdc.txt output/textdocs/Samba4-HOWTO/bdc.txt output/textdocs/Samba4-HOWTO/domain-member.txt output/textdocs/Samba4-HOWTO/ad-dc.txt output/textdocs/Samba4-HOWTO/ad-member.txt output/textdocs/Samba4-HOWTO/shares.txt output/textdocs/Samba4-HOWTO/printing.txt output/textdocs/Samba4-HOWTO/authentication.txt output/textdocs/Samba4-HOWTO/registry.txt output/textdocs/Samba4-HOWTO/smbclient.txt output/textdocs/Samba4-HOWTO/cifsfs.txt output/textdocs/Samba4-HOWTO/gui-clients.txt output/textdocs/Samba4-HOWTO/compiling.txt 
Samba4-HOWTO-images-latex-svg = $(wildcard $(addsuffix .svg, $(Samba4-HOWTO-images-latex)))
Samba4-HOWTO-images-latex-eps: $(addsuffix .eps, $(Samba4-HOWTO-images-latex))
Samba4-HOWTO-images-latex-pdf: $(patsubst %.svg, %.pdf, $(Samba4-HOWTO-images-latex-svg))
Samba4-HOWTO-images-latex-png: $(filter-out $(patsubst %.svg,%.png,$(Samba4-HOWTO-images-latex-svg)), $(addsuffix .png, $(Samba4-HOWTO-images-latex)))

$(HTMLDIR)/%: Samba4-HOWTO/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLDIR)/Samba4-HOWTO/%: Samba4-HOWTO/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLHELPDIR)/Samba4-HOWTO/%: Samba4-HOWTO/%
	@mkdir -p $(@D)
	@cp $< $@

Samba4-HOWTO-images-html-single: $(addprefix $(HTMLDIR)/, $(Samba4-HOWTO-images-html))
Samba4-HOWTO-images-html-chunks: $(addprefix $(HTMLDIR)/Samba4-HOWTO/, $(Samba4-HOWTO-images-html))
Samba4-HOWTO-images-htmlhelp: $(addprefix $(HTMLHELPDIR)/Samba4-HOWTO/, $(Samba4-HOWTO-images-html))
