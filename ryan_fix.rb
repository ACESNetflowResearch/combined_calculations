#!/usr/bin/ruby
require 'mysql'
require_relative 'cmu_features'
require_relative 'sig_features'
begin

    puts("ip, rt_w/o_ACK, rt_under_3, max_ips_1sub, max_high, max_low, max_cnsc_high, max_cnsc_low, num_uniq_dsts, num_uniq_srcp, avg_srcp/dst, rt_std_flags, rt_over_60, med_pack/dst, rt_std_pttrn, rt_bksctr_pttrn, rt_dst, rt_srcp, rt_bksctr_flags, min_pack, max_pack, mean_pack, std_dev_pack, min_dur, max_dur, mean_dur, std_dev_dur, min_bytes, max_bytes, mean_bytes, std_dev_bytes, min_bpp, max_bpp, mean_bpp, std_dev_bpp, tcp_count, udp_count, label")

    #usage ARGS 0 = dec or nov, 1 = 0 or 1 for malicious or benign
    month = ARGV[0]
    label = ARGV[1]
    con = Mysql.new 'localhost', 'root', 'cyberaces', 'netflow_db'
    all_src_ips = con.query("SELECT DISTINCT ip FROM ip_labels_#{month}_4 WHERE label = '#{label}'") #get all the distinct src IPS
    #for each src IP, caclulate it's statistics by grabbing all its flows and processing them
    all_src_ips.each do |ip|
	   c = IP_Stat_Calculator.new
	   s = Calculate_sigcomm_features.new
	   ip_data = con.query("SELECT * FROM netflow_#{month} WHERE src_IP = '#{ip[0]}'")
	   if ip_data.num_rows() < 10 then next end
	   ip_data.each do |flow|
		  c.total_flows += 1
		  c.has_no_ACK_flag(flow[7])
		  c.has_standard_flags(flow[7])
		  c.has_under_3_packets(flow[9].to_i)
		  c.has_over_60_Bpp(flow[13].to_i)
		  c.has_standard_pattern(flow[7], flow[13].to_i, flow[9].to_i)
		  c.has_backscatter_flags(flow[7])
		  c.has_backscatter_pattern(flow[7], flow[13].to_i, flow[9].to_i)
		  c.src_port_hash[flow[4]] = 1
		  c.subnet_identify(flow[5])

		  c.calculate_initial_dst_IP_stats(flow)
		  s.ctr = s.ctr + 1
		  s.packet_stats(flow[9].to_f) 
		  s.duration_stats(flow[1].to_f)
		  s.bytes_stats(flow[10].to_f)
		  s.bpp_stats(flow[13].to_f)
		  s.udp_tcp_ratio(flow[2])
	   end
	   
	   c.calculate_end_dst_IP_stats()
	   s.std_packets = Math.sqrt(s.std_packets_sum/s.ctr)
	   s.std_duration = Math.sqrt(s.std_duration_sum/s.ctr)
	   s.std_bytes = Math.sqrt(s.std_bytes_sum/s.ctr)
	   s.std_bpp = Math.sqrt(s.std_bpp_sum/s.ctr)

	   #print in csv format 
	   
	   puts("#{ip[0]}, #{c.without_ACK_cnt.to_f/c.total_flows.to_f}, #{c.under_3_packets_cnt.to_f/c.total_flows.to_f}, #{c.subnet_hash.values.sort.last}, #{c.max_high_ports}, #{c.max_low_ports},  #{c.max_consec_high}, #{c.max_consec_low}, #{c.dst_IP_hash.length}, #{c.src_port_hash.length}, #{c.avg_src_ports_per_dst_IP}, #{c.standard_flags_cnt.to_f/c.total_flows.to_f}, #{c.over_60_Bpp_cnt.to_f/c.total_flows.to_f}, #{c.median_packets_per_dst_IP},  #{c.standard_pattern_cnt.to_f/c.total_flows.to_f}, #{c.backscatter_pattern_cnt.to_f/c.total_flows.to_f},  #{c.dst_IP_hash.length.to_f/c.total_flows.to_f}, #{c.src_port_hash.length.to_f/c.total_flows.to_f}, #{c.backscatter_flags_cnt.to_f/c.total_flows.to_f}, #{s.min_packets}, #{s.max_packets}, #{s.packets_total/s.ctr},  #{s.std_packets}, #{s.min_duration}, #{s.max_duration}, #{s.duration_total/s.ctr}, #{s.std_duration}, #{s.min_bytes}, #{s.max_bytes}, #{s.bytes_total/s.ctr}, #{s.std_bytes}, #{s.min_bpp}, #{s.max_bpp}, #{s.bpp_total/s.ctr}, #{s.std_bpp}, #{s.tcp}, #{s.udp}, #{label}")
=begin	   
	   puts("IP: #{ip[0]}")
	   #cmu
	   puts("rt_w/o_ACK: #{c.without_ACK_cnt.to_f/c.total_flows.to_f}") #1
	   puts("rt_under_3: #{c.under_3_packets_cnt.to_f/c.total_flows.to_f}") #2
	   puts("max_ips_1sub: #{c.subnet_hash.values.sort.last}") #3
	   puts("max_high: #{c.max_high_ports}") #4
	   puts("max_low: #{c.max_low_ports}") #5
	   puts("max_cnsc_high: #{c.max_consec_high}") #6 
	   puts(" max_cnsc_low: #{c.max_consec_low}") #7
	   puts("num_uniq_dsts: #{c.dst_IP_hash.length}") #8
	   puts("num_uniq_srcp: #{c.src_port_hash.length}") #9
	   puts("avg_srcp/dst: #{c.avg_src_ports_per_dst_IP}") #10
	   puts("rt_std_flags: #{c.standard_flags_cnt.to_f/c.total_flows.to_f}") #11 
	   puts("rt_over_60: #{c.over_60_Bpp_cnt.to_f/c.total_flows.to_f}") #12
	   puts("med_pack/dst: #{c.median_packets_per_dst_IP}") #13
	   puts("rt_std_pttrn: #{c.standard_pattern_cnt.to_f/c.total_flows.to_f}") #14
	   puts("rt_bksctr_pttrn: #{c.backscatter_pattern_cnt.to_f/c.total_flows.to_f}") #15
	   puts("rt_dst: #{c.dst_IP_hash.length.to_f/c.total_flows.to_f}") #16
	   puts("rt_srcp: #{c.src_port_hash.length.to_f/c.total_flows.to_f}") #17
	   puts("rt_bksctr_flags: #{c.backscatter_flags_cnt.to_f/c.total_flows.to_f}") #18	 
	 #sigcomm
	   puts("min_pack: #{s.min_packets}")
	   puts("max_pack: #{s.max_packets}") 
	   puts("mean_pack: #{s.packets_total/s.ctr}")
	   puts("std_dev_pack: #{s.std_packets}")
	   puts("min_dur: #{s.min_duration}")
	   puts("max_dur: #{s.max_duration}")
	   puts("mean_dur: #{s.duration_total/s.ctr}")
	   puts("std_dev_dur: #{s.std_duration}")
	   puts("min_bytes: #{s.min_bytes}")
	   puts("max_bytes: #{s.max_bytes}")
	   puts("mean_bytes: #{s.bytes_total/s.ctr}")
	   puts("std_dev_bytes: #{s.std_bytes}")
	   puts("min_bpp: #{s.min_bpp}")
	   puts("max_bpp: #{s.max_bpp}")
	   puts("mean_bpp: #{s.bpp_total/s.ctr}")
	   puts("std_dev_bpp: #{s.std_bpp}")
	   puts("tcp_count: #{s.tcp}")
	   puts("udp_count: #{s.udp}")
	   puts("Next IP")
=end
    end
rescue Mysql::Error => e
    puts e.errno
    puts e.error
ensure
    con.close if con
end


