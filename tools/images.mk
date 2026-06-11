# SPDX-FileCopyrightText: Copyright 2018-2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

# Makefile for building image files (SVG and PDF) from sources

# The parameter $(IMAGE) must have the location of the image files
IMAGE			= .

# This makefile
MAKEFILE		= $(lastword $(MAKEFILE_LIST))
# The location of this makefile, relative to the current directory
MAKEFILEDIR		:= $(patsubst %/,%,$(dir $(MAKEFILE)))
# The location of the psa-api-tool tools, containing the PlantUML configuration
SPEC			= $(MAKEFILEDIR)

# Bitfield image generation, command to run to wavedrompy
WAVEDROM		= wavedrompy

# UML image generation, command to run plantuml
JAVA			= java
PLANTUML_IPATH	= $(SPEC)/puml
PLANTUML		= $(JAVA) -Dplantuml.include.path="$(PLANTUML_IPATH)" -jar ~/jar/plantuml.jar
PLANTUML_FLAGS	= -nometadata -tsvg -charset utf-8

# SVG to PDF conversion
SVG2PDF       = rsvg-convert
SVG2PDF_FLAGS = --format=pdf

OSTYPE = $(shell echo $${OSTYPE})
ifneq (,$(filter darwin%,$(OSTYPE)))
	SED_FLAG = -i ''
else ifneq (,$(filter bsd%,$(OSTYPE)))
	SED_FLAG = -i ''
else
	SED_FLAG = -i''
endif

FIX_SVG_FONTS = sed $(SED_FLAG) -e 's/"roboto mono"/"Roboto Mono,monospace"/gi;s/"roboto"/"Roboto,sans-serif"/gi;s/lato/Lato,sans-serif/gi;s/inconsolata/Inconsolata,monospace/gi'

# Images can be in sub-directories of those listed in $IMAGE
IMAGES := $(shell find $(IMAGE) -type d -print)

# List of UML diagrams to render
UML_IMAGES := $(wildcard $(addsuffix /*.puml,$(IMAGES)))
# List of bitfield descriptions to render
BIT_IMAGES := $(wildcard $(addsuffix /*.json,$(IMAGES)))
# Build a list of source SVG image files to convert
SVG_IMAGES := $(sort $(patsubst %.json,%.svg,$(BIT_IMAGES))   \
					 $(patsubst %.puml,%.svg,$(UML_IMAGES))   \
					 $(wildcard $(addsuffix /*.svg,$(IMAGES))) \
				)
# Build a list of generated PDF files
PDF_IMAGES := $(patsubst %.svg,%.pdf,$(SVG_IMAGES))

PUML_INCLUDES := $(wildcard $(PLANTUML_IPATH)/*)

# Pattern rule for identifying UML files to rebuild
%.svg : %.puml $(MAKEFILE) $(PUML_INCLUDES)
	@echo "Rendering $<"; \
	$(PLANTUML) $(PLANTUML_FLAGS) $< ;	\
	$(FIX_SVG_FONTS) $@

# Pattern rule for converting JSON to SVG
%.svg : %.json $(MAKEFILE)
	@echo "Rendering $<";	\
	$(WAVEDROM) -i $< -s $@; \
	$(FIX_SVG_FONTS) $@

# Pattern rule for identifying SVG files to convert
%.pdf : %.svg
	@echo "Converting $<";	\
	$(SVG2PDF) $(SVG2PDF_FLAGS) -o $@ $<

.PHONY: all
all: svg pdf

.PHONY: svg
svg: $(SVG_IMAGES)

.PHONY: pdf
pdf: $(PDF_IMAGES)

.PHONY: help
help:
	@echo "To build the graphics, please use \`make <target>' where <target> is one of"; \
	echo "  svg   to make the SVG image files"; \
	echo "  pdf   to make the PDF image files"; \
	echo ""; \
	echo "  all   to make all image files"
