#!/usr/bin/ruby
#require 'mysql'

class Calculate_sigcomm_features
    attr_accessor :ctr, :min_packets, :max_packets, :packets_total, :std_packets_sum, :std_packets, :min_duration, :max_duration, :duration_total, :std_duration_sum, :std_duration,
	   :min_bytes, :max_bytes, :bytes_total, :std_bytes_sum, :std_bytes, :min_bpp, :max_bpp, :bpp_total, :std_bpp_sum, :std_bpp, :udp, :tcp 
    def initialize
	   @ctr = 0
	   @min_packets=nil
	   @max_packets=nil
	   @packets_total=0.0
	   @std_packets_sum=0.0
	   @std_packets=0.0
	   
	   @min_duration=nil
	   @max_duration=nil
	   @duration_total=0.0
	   @std_duration_sum=0.0
	   @std_duration=0.0
    
	   @min_bytes=nil
	   @max_bytes=nil
	   @bytes_total=0.0
	   @std_bytes_sum=0.0
	   @std_bytes=0.0
    
	   @min_bpp=nil
	   @max_bpp=nil
	   @bpp_total=0.0
	   @std_bpp_sum=0.0
	   @std_bpp=0.0

	   @udp = 0
	   @tcp = 0
    end

    def udp_tcp_ratio(protocol)
	   #puts("#{protocol}")
	   if protocol.eql? "UDP"
		  @udp = @udp + 1
	   elsif protocol.eql? "TCP"
		  @tcp = @tcp + 1
	   end
    
    end

    def packet_stats(packets)
	   if @min_packets == nil
		  @min_packets = packets
	   elsif @min_packets > packets
		  @min_packets = packets
	   end

	   if @max_packets == nil
		  @max_packets = packets
	   elsif @max_packets < packets
		  @max_packets = packets
	   end

	   @packets_total = @packets_total + packets
	   @std_packets_sum = @std_packets_sum + (packets - (@packets_total/@ctr))*(packets - (@packets_total/@ctr))
    end

    def duration_stats(duration)
	   if @min_duration == nil
		  @min_duration = duration
	   elsif @min_duration > duration
		  @min_duration = duration
	   end

	   if @max_duration == nil
		  @max_duration = duration
	   elsif @max_duration < duration
		  @max_duration = duration
	   end

	   @duration_total = @duration_total + duration
	   @std_duration_sum = @std_duration_sum + (duration - (@duration_total/@ctr))*(duration - (@duration_total/@ctr))   
    end

    def bytes_stats(bytes)
	   if @min_bytes == nil
		  @min_bytes = bytes
	   elsif @min_bytes > bytes
		  @min_bytes = bytes
	   end

	   if @max_bytes == nil
		  @max_bytes = bytes
	   elsif @max_bytes < bytes
		  @max_bytes = bytes
	   end

	   @bytes_total = @bytes_total + bytes
	   @std_bytes_sum = @std_bytes_sum + (bytes - (@bytes_total/@ctr))*(bytes - (@bytes_total/@ctr))
    end

    def bpp_stats(bpp)
	   if @min_bpp == nil
		  @min_bpp = bpp
	   elsif @min_bpp > bpp
		  @min_bpp = bpp
	   end         
	   
	   if @max_bpp == nil
		  @max_bpp = bpp
	   elsif @max_bpp < bpp
		  @max_bpp = bpp
	   end      
	   
	   @bpp_total = @bpp_total + bpp
	   @std_bpp_sum = @std_bpp_sum + (bpp - (@bpp_total/@ctr))*(bpp - (@bpp_total/@ctr))
    end
end
=begin
begin
     con = Mysql.new 'localhost', 'root', 'cyberaces', 'netflow_db' #open connection
	all_src_ips = con.query("SELECT DISTINCT src_IP FROM netflow_full_2") #get all the distinct src IPS
	 all_src_ips.each{ |ip|
		 c = Calculate_sigcomm_features.new
		 ip_data = con.query("SELECT * FROM netflow_full WHERE src_IP = '#{ip[0]}'")
		 ip_data.each{|flow|
			 c.ctr = c.ctr + 1
			 c.packet_stats(flow[9].to_f)
			 c.duration_stats(flow[1].to_f)
			 c.bytes_stats(flow[10].to_f)
			 c.bpp_stats(flow[13].to_f)
		 }
	   c.std_packets = Math.sqrt(c.std_packets_sum/c.ctr)
	   c.std_duration = Math.sqrt(c.std_duration_sum/c.ctr)
	   c.std_bytes = Math.sqrt(c.std_bytes_sum/c.ctr)
	   c.std_bpp = Math.sqrt(c.std_bpp_sum/c.ctr)

	   puts("IP: #{ip[0]}")
	   puts("min packets: #{c.min_packets}, max packets: #{c.max_packets}, mean packets: #{c.packets_total/c.ctr}, standard deviation of packets: #{c.std_packets}")
	   puts("min duration: #{c.min_duration}, max duration: #{c.max_duration}, mean duration: #{c.duration_total/c.ctr}, standard deviation of duration: #{c.std_duration}")
	   puts("min bytes: #{c.min_bytes}, max bytes: #{c.max_bytes}, mean bytes: #{c.bytes_total/c.ctr}, standard deviation of bytes: #{c.std_bytes}")
	   puts("min bpp: #{c.min_bpp}, max bpp: #{c.max_bpp}, mean bpp: #{c.bpp_total/c.ctr}, standard deviation of bpp: #{c.std_bpp}")
	 }

rescue Mysql::Error => e
    puts e.errno
    puts e.error
ensure
    con.close if con
end
=end
