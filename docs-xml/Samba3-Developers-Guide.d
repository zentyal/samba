Samba3-Developers-Guide-images- = 
Samba3-Developers-Guide-txt-chunks: output/textdocs/Samba3-Developers-Guide/index.txt output/textdocs/Samba3-Developers-Guide/unix-smb.txt output/textdocs/Samba3-Developers-Guide/ntdomain.txt output/textdocs/Samba3-Developers-Guide/architecture.txt output/textdocs/Samba3-Developers-Guide/debug.txt output/textdocs/Samba3-Developers-Guide/internals.txt output/textdocs/Samba3-Developers-Guide/CodingSuggestions.txt output/textdocs/Samba3-Developers-Guide/contributing.txt output/textdocs/Samba3-Developers-Guide/modules.txt output/textdocs/Samba3-Developers-Guide/rpc-plugin.txt output/textdocs/Samba3-Developers-Guide/vfs.txt output/textdocs/Samba3-Developers-Guide/parsing.txt output/textdocs/Samba3-Developers-Guide/wins.txt output/textdocs/Samba3-Developers-Guide/pwencrypt.txt output/textdocs/Samba3-Developers-Guide/tracing.txt output/textdocs/Samba3-Developers-Guide/devprinting.txt output/textdocs/Samba3-Developers-Guide/Packaging.txt 
Samba3-Developers-Guide-images-latex-svg = $(wildcard $(addsuffix .svg, $(Samba3-Developers-Guide-images-latex)))
Samba3-Developers-Guide-images-latex-eps: $(addsuffix .eps, $(Samba3-Developers-Guide-images-latex))
Samba3-Developers-Guide-images-latex-pdf: $(patsubst %.svg, %.pdf, $(Samba3-Developers-Guide-images-latex-svg))
Samba3-Developers-Guide-images-latex-png: $(filter-out $(patsubst %.svg,%.png,$(Samba3-Developers-Guide-images-latex-svg)), $(addsuffix .png, $(Samba3-Developers-Guide-images-latex)))

$(HTMLDIR)/%: Samba3-Developers-Guide/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLDIR)/Samba3-Developers-Guide/%: Samba3-Developers-Guide/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLHELPDIR)/Samba3-Developers-Guide/%: Samba3-Developers-Guide/%
	@mkdir -p $(@D)
	@cp $< $@

Samba3-Developers-Guide-images-html-single: $(addprefix $(HTMLDIR)/, $(Samba3-Developers-Guide-images-html))
Samba3-Developers-Guide-images-html-chunks: $(addprefix $(HTMLDIR)/Samba3-Developers-Guide/, $(Samba3-Developers-Guide-images-html))
Samba3-Developers-Guide-images-htmlhelp: $(addprefix $(HTMLHELPDIR)/Samba3-Developers-Guide/, $(Samba3-Developers-Guide-images-html))
