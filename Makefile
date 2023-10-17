
EXPDATADIR = ./experiments/
BUILDDIR = ./build/




.PHONY: clean-data
clean-data:
	find $(EXPDATADIR) -type f -name "*.csv" -delete
	find $(EXPDATADIR) -type f -name "*.txt" -delete
	find $(EXPDATADIR) -type f -name "*.zip" -delete
	
	


# find $(BUILDDIR) -type d -name "*" -exec rm -r {} +