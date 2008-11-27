test-images- = 
test-txt-chunks: output/textdocs/test/index.txt 
test-images-latex-svg = $(wildcard $(addsuffix .svg, $(test-images-latex)))
test-images-latex-eps: $(addsuffix .eps, $(test-images-latex))
test-images-latex-pdf: $(patsubst %.svg, %.pdf, $(test-images-latex-svg))
test-images-latex-png: $(filter-out $(patsubst %.svg,%.png,$(test-images-latex-svg)), $(addsuffix .png, $(test-images-latex)))

$(HTMLDIR)/%: test/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLDIR)/test/%: test/%
	@mkdir -p $(@D)
	@cp $< $@

$(HTMLHELPDIR)/test/%: test/%
	@mkdir -p $(@D)
	@cp $< $@

test-images-html-single: $(addprefix $(HTMLDIR)/, $(test-images-html))
test-images-html-chunks: $(addprefix $(HTMLDIR)/test/, $(test-images-html))
test-images-htmlhelp: $(addprefix $(HTMLHELPDIR)/test/, $(test-images-html))
