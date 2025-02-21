.PHONY: all clean build install uninstall

VERSION = 1.0.0
PACKAGE_NAME = mask-cli_$(VERSION)

all: build

build:
	@echo "Building MASK CLI package..."
	@bash build-deb.sh

clean:
	@echo "Cleaning build files..."
	@rm -rf $(PACKAGE_NAME)
	@rm -f $(PACKAGE_NAME).deb

install:
	@echo "Installing MASK CLI..."
	@sudo dpkg -i $(PACKAGE_NAME).deb
	@sudo apt-get install -f

uninstall:
	@echo "Uninstalling MASK CLI..."
	@sudo dpkg -r mask-cli 