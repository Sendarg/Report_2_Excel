#!/usr/bin/env ruby

# == neXCSer: Nessus V2 XML to CSV parser
#
# neXCSer will take a Nessus version 2 XML file and create two CSV files, a summary of machines scanned
# and a detailed breakdown of the plugin outputs.
#
# == Usage
#
# neXCSer [OPTION] ... NESSUS_XML
#
# --help, -h:
#	show help
#
# --no-summary:
#	don't create the summary
#
# --no-detail:
#	don't create the detailed report
#
# --summary-name -s:
#	the name of the summary file, default summary.csv
#
# --detail-name -s:
#	the name of the detail file, default detail.csv
#
# --verbose -v
#	verbose
#
# --quiet -q:
#	no output
#
# NESSUS_XML: the name of the Nessus file
#
# Author:: Robin Wood (dninja@gmail.com)
# Copyright:: Copyright (c) Robin Wood 2010
# Licence:: Creative Commons Attribution-Share Alike 2.0 UK: England & Wales (http://creativecommons.org/licenses/by-sa/2.0/uk/)
#

require 'getoptlong'
require 'rexml/document'
require 'csv'

opts = GetoptLong.new(
	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
	[ '--quiet', '-q', GetoptLong::NO_ARGUMENT ],
	[ '--no-summary', GetoptLong::NO_ARGUMENT ],
	[ '--no-detail', GetoptLong::NO_ARGUMENT ],
	[ '--summary-name', "-s" , GetoptLong::REQUIRED_ARGUMENT ],
	[ '--detail-name', "-d" , GetoptLong::REQUIRED_ARGUMENT ],
	[ "--verbose", "-v" , GetoptLong::NO_ARGUMENT ]
)

# Display the usage
def usage
	puts"neXCSer 1.0 Robin Wood (robin@digininja.org) (www.digininja.org)

Usage: neXCSer [OPTION] ... NESSUS_XML
 --help, -h: show help
 --no-summary: don't create the summary
 --no-detail: don't create the detailed report
 --summary-name -s: the name of the summary file, default summary.csv
 --detail-name -s: the name of the detail file, default detail.csv
 --quiet -q: no output
 --verbose -v verbose

    NESSUS_XML: the name of the Nessus file

"
	exit
end

create_summary = true
create_detailed = true
summary_filename = "summary.csv"
detail_filename = "detail.csv"
quiet = false
verbose = false
xml_file = nil

begin
	opts.each do |opt, arg|
		case opt
		when '--help'
			usage
		when "--quiet"
			quiet=true
		when "--no-summary"
			create_summary=false
		when "--no-detail"
			create_detailed = false
		when '--verbose'
			verbose=true
		when '--summary-name'
			summary_filename=arg
		when '--detail-name'
			detail_filename=arg
		end
	end
rescue
	usage
end

if !(create_detailed and create_summary)
	puts "Not creating summary or detailed report so nothing to do, how about a little xkcd instead http://xkcd.com/ ?"
	exit
end

if ARGV.length != 1
	puts "Missing Nessus XML argument (try --help)"
	exit 0
end

xml_file = ARGV.shift

if !File.exists?(xml_file)
	puts "The Nessus file specified can't be found"
	exit
end

xml_data = File.open(xml_file, "r").read

begin
	doc = REXML::Document.new(xml_data)
rescue REXML::ParseException
	puts "There was a problem parsing the XML file"
	exit
rescue
	puts "There was a problem with the XML file"
end

if create_summary
	begin
		summary_outfile = File.open(summary_filename, 'w')
	rescue
		puts "Couldn't open the summary file for writing"
		exit
	end
	summary_csv = CSV::Writer.generate(summary_outfile)
	summary_csv << ["name", "os", "mac", "ip", "fqdn", "netbios"]
end

if create_detailed
	begin
		detailed_outfile = File.open(detail_filename, 'w')
	rescue
		puts "Couldn't open the detailed file for writing"
		exit
	end
	detailed_csv = CSV::Writer.generate(detailed_outfile)
	detailed_csv << ["name", "port", "svc_name", "protocol", "severity", "pluginID", "pluginName", "pluginFamily", "bid", "cve", "cvss_base_score", "cvss_vector", "description", "patch_publication_date", "plugin_output", "plugin_publication_date", "plugin_version", "risk_factor", "see_also", "solution", "synopsis", "vuln_publication_date", "xref"]
end

machines_processed = 0

begin
	doc.elements.each('NessusClientData_v2/Report/ReportHost') { |ele|
		name = ele.attributes["name"]
		if (name == "SCAN-ERROR")
			next
		end
		if !quiet
			puts "Processing: " + name
		end
		machines_processed += 1

		if create_summary
			summary = {
						"HOST_START" => "",
						"HOST_END" => "",
						"operating-system" => "",
						"mac-address" => "",
						"host-ip" => "",
						"host-fqdn" => "",
						"netbios-name" => "",
					}

			ele.elements.each("HostProperties/tag") { |props|
				if (props.attributes.has_key?("name"))
					tag_name = props.attributes["name"]
					tag_value = props.get_text.to_s

					if summary.has_key?(tag_name)
						summary[tag_name] = tag_value
					else
						if verbose
							puts "Found unknown summary tag: " + tag_name
						end
					end
				end
			}
			summary_csv << [name, summary["operating-system"], summary["mac-address"], summary["host-ip"], summary["host-fqdn"], summary["netbios-name"],]
		end

		if create_detailed
			ele.elements.each("ReportItem") { |props|
				attrs = {
							"name" => name,
							"port" => "",
							"svc_name" => "",
							"protocol" => "",
							"severity" => "",
							"pluginID" => "",
							"pluginName" => "",
							"pluginFamily" => "",
						}
				details = {
							"bid" => "",
							"cve" => "",
							"cvss_base_score" => "",
							"cvss_vector" => "",
							"description" => "",
							"patch_publication_date" => "",
							"plugin_output" => "",
							"plugin_publication_date" => "",
							"plugin_version" => "",
							"risk_factor" => "",
							"see_also" => "",
							"solution" => "",
							"synopsis" => "",
							"vuln_publication_date" => "",
							"xref" => "",
						}

				attrs.each { |attr_name,value|
					if (props.attributes.has_key?(attr_name))
						attrs[attr_name] = props.attributes[attr_name]
					end
				}

				if props.has_elements?
					props.each_element { |elem|
						if details.has_key?(elem.name)
							if details[elem.name] == ""
								details[elem.name] = elem.text
							else
								details[elem.name] = details[elem.name] + "\n" + elem.text
							end
						else
							if verbose
								puts "Unknown key " + elem.name
							end
						end
					}
				end

				detailed_csv << [attrs["name"], attrs["port"], attrs["svc_name"], attrs["protocol"], attrs["severity"], attrs["pluginID"], attrs["pluginName"], attrs["pluginFamily"], details["bid"], details["cve"], details["cvss_base_score"], details["cvss_vector"], details["description"], details["patch_publication_date"], details["plugin_output"], details["plugin_publication_date"], details["plugin_version"], details["risk_factor"], details["see_also"], details["solution"], details["synopsis"], details["vuln_publication_date"], details["xref"],]

				# could do it like this but the values method messes up the order of the columns so doing it by hand instead
				# detailed_csv << attrs.values.reverse
			}
		end
	}
rescue
	puts "There was a problem processing the XML file"
	exit
end

if !quiet
	puts
	puts "Processed " + machines_processed.to_s + " records"
	if create_summary
		puts "Summary file created: " + summary_filename
	end
	if create_detailed
		puts "Detail file created: " + detail_filename
	end
end

if create_summary
	summary_outfile.close
end
if create_detailed
	detailed_outfile.close
end
