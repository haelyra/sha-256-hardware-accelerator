module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, rst_n, start,
 input logic  [15:0] input_addr, hash_addr,
 output logic done, memory_clk, enable_write,
 output logic [15:0] memory_addr,
 output logic [31:0] memory_write_data,
 input logic [31:0] memory_read_data);

// FSM state variables
typedef enum logic [4:0]{IDLE, BLOCK, COMPUTE, WRITE,
	FILL_DECIDE, FILL_ADDR, FILL_WAIT, FILL_CAP, 
	BLOCK_INIT, BLOCK_DONE, WR_PULSE, WR_HOLD, WR_NEXT
}state_t;

state_t state;


parameter int SIZE = NUM_OF_WORDS * 32;

localparam int NUM_BLOCKS = ((NUM_OF_WORDS + 2) / 16) + 1;
localparam int TOTAL_WORDS  = NUM_BLOCKS * 16;


// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


// Local variables
logic [31:0] w[64];
logic [31:0] message[16];
logic [31:0] wt;
logic [31:0] S0,S1;
logic [31:0] hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
logic [31:0] base0, base1, base2, base3, base4, base5, base6, base7;
logic [31:0] A, B, C, D, E, F, G, H;
logic [ 7:0] i, j;
logic [7:0] offset; // in word address
logic [ 7:0] num_blocks;
//logic        enable_write;
logic [15:0] present_addr;
logic [31:0] present_write_data;
logic [512:0] data_read;
logic [ 7:0] tstep;

logic [7:0] word_idx;




// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign memory_clk = clk;
assign memory_addr = present_addr;
assign memory_we = enable_write;
assign memory_write_data = present_write_data;


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
											input logic [7:0] t);
		logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
		begin
			S1= ror(e, 8'd6) ^ ror(e,8'd11) ^ ror(e,8'd25);
			ch= (e&f) ^ ((~e)&g);
			t1 = h + S1 + ch + k[t] + w;
			
			S0 = ror(a,8'd2) ^ ror(a,8'd13) ^ ror(a,8'd22);
			maj = (a&b) ^ (a&c) ^ (b&c);
			t2 = S0 +maj;
			
			sha256_op = {t1+t2, a, b, c, d+t1, e, f, g};
end
endfunction


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] ror(input logic [31:0] in, input logic [7:0] s);
	logic [31:0] a1, a2;
	begin
		a1=(in>>s);
		a2=(in<<(8'd32-s));
		ror=(a1|a2);
end
endfunction

// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_comb begin
    if (state == IDLE) begin
        done = 1'b1;
    end else begin
        done = 1'b0;
    end
end

always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state <= IDLE;
        enable_write <= 1'b0;
        present_addr <= 16'd0;
        present_write_data <= 32'd0;
        offset <= 8'd0;
        word_idx <= 8'd0;
        i <= 8'd0;
        j <= 8'd0;
        hash0 <= 32'd0; 
		  hash1 <= 32'd0;
		  hash2 <= 32'd0;
		  hash3 <= 32'd0;
        hash4 <= 32'd0;
		  hash5 <= 32'd0;
		  hash6 <= 32'd0;
		  hash7 <= 32'd0;
        base0 <= 32'd0;
		  base1 <= 32'd0;
		  base2 <= 32'd0;
		  base3 <= 32'd0;
        base4 <= 32'd0;
		  base5 <= 32'd0;
		  base6 <= 32'd0;
		  base7 <= 32'd0;
        A <= 32'd0;
		  B <= 32'd0;
		  C <= 32'd0;
		  D <= 32'd0;
        E <= 32'd0;
		  F <= 32'd0;
		  G <= 32'd0;
		  H <= 32'd0;
		  
        for(int i=0; i<16; i++)begin
            message[i] <= 32'd0;
        end
    end 
	 else begin
        case (state)
		  
            // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
            IDLE: begin
                enable_write <= 1'b0;
                present_addr <= 16'd0;
                present_write_data <= 32'd0;
					 
                if(start==1'b1)begin
                    hash0 <= 32'h6a09e667;
                    hash1 <= 32'hbb67ae85;
                    hash2 <= 32'h3c6ef372;
                    hash3 <= 32'ha54ff53a;
                    hash4 <= 32'h510e527f;
                    hash5 <= 32'h9b05688c;
                    hash6 <= 32'h1f83d9ab;
                    hash7 <= 32'h5be0cd19;
                    offset <= 8'd0;
                    word_idx <= 8'd0;
                    state <= FILL_DECIDE;
                end else begin
                    state <= IDLE;
                end
            end
				
            FILL_DECIDE: begin
                int idx;
                logic [31:0] m;
                idx = (offset * 16) + word_idx;
                m = 32'h00000000;
                if(idx < NUM_OF_WORDS)begin
                    state <= FILL_ADDR;
                end 
					 else begin
                    if(idx == NUM_OF_WORDS)begin
                        m = 32'h80000000;
                    end 
						  else begin
                        if(idx == (TOTAL_WORDS - 1))begin
                            m = SIZE[31:0];
                        end
								else begin
									m = 32'h00000000;
                        end
                    end
						  
                    message[word_idx] <= m;
						  
                    if(word_idx == 8'd15)begin
                        state <= BLOCK_INIT;
                    end
						  else begin
                        word_idx <= word_idx + 8'd1;
                        state <= FILL_DECIDE;
                    end
                end
            end
				
            FILL_ADDR: begin
                int idx;
                idx =(offset*16) + word_idx;
                enable_write <= 1'b0;
                present_addr <= input_addr + idx[15:0];
                state <= FILL_WAIT;
            end
				
            FILL_WAIT: begin
                state <= FILL_CAP;

            end

            FILL_CAP: begin
                message[word_idx] <= memory_read_data;
                if(word_idx == 8'd15)begin
                    state <= BLOCK_INIT;
                end 
					 else begin
                    word_idx <= word_idx + 8'd1;
                    state <= FILL_DECIDE;
                end
            end

            // For each block compute hash function
				// Go back to BLOCK stage after each block hash computation is completed and if
				// there are still number of message blocks available in memory otherwise
				// move to WRITE stage
            BLOCK_INIT: begin
                base0 <= hash0;
					 base1 <= hash1;
					 base2 <= hash2;
					 base3 <= hash3;
                base4 <= hash4;
					 base5 <= hash5;
					 base6 <= hash6;
					 base7 <= hash7;
                A <= hash0; 
					 B <= hash1; 
					 C <= hash2;
					 D <= hash3;
                E <= hash4; 
					 F <= hash5; 
					 G <= hash6; 
					 H <= hash7;
                i <= 8'd0;
                state <= COMPUTE;
            end
				
            // 64 processing rounds steps for 512-bit block
            COMPUTE: begin
                logic [31:0] wt, s0, s1, wtnew;
                logic [255:0] nxt;
					 
                wt = message[0];
                s0 = ror(message[1], 8'd7) ^ ror(message[1], 8'd18) ^ (message[1] >> 3);
                s1 = ror(message[14], 8'd17) ^ ror(message[14], 8'd19) ^ (message[14] >> 10);
                wtnew = message[0] + s0 + message[9] + s1;
                nxt = sha256_op(A, B, C, D, E, F, G, H, wt, i);
					 
                A <= nxt[255:224];
                B <= nxt[223:192];
                C <= nxt[191:160];
                D <= nxt[159:128];
                E <= nxt[127:96];
                F <= nxt[95:64];
                G <= nxt[63:32];
                H <= nxt[31:0];
                if(i != 8'd63)begin
                    for(int i= 0; i < 15; i++)begin
                        message[i] <= message[i + 1];
                    end
                    message[15] <= wtnew;
                    i <= i + 8'd1;
                    state <= COMPUTE;
                end
					 else begin
                    state <= BLOCK_DONE;
                end
            end

           	// SHA-256 FSM 
				// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
				// and write back hash value back to memory
            BLOCK_DONE: begin
				
                hash0 <= base0 + A;
                hash1 <= base1 + B;
                hash2 <= base2 + C;
                hash3 <= base3 + D;
                hash4 <= base4 + E;
                hash5 <= base5 + F;
                hash6 <= base6 + G;
                hash7 <= base7 + H;
					 
                if(offset == (NUM_BLOCKS - 1)) begin
                    j <= 8'd0;
                    state <= WRITE;
                end
					 else begin
                    offset <= offset + 8'd1;
                    word_idx <= 8'd0;
                    state <= FILL_DECIDE;
                end
            end

            // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
				// h0 to h7 after compute stage has final computed hash value
				// write back these h0 to h7 to memory starting from output_addr

            WRITE: begin
				
                enable_write <= 1'b0;
                present_addr <= hash_addr + {8'd0, j};
                if(j == 8'd0)begin
                    present_write_data <= hash0;
                end
					 else begin
						if(j == 8'd1)begin
							present_write_data <= hash1;
                  end
						else begin
							if(j == 8'd2)begin
								present_write_data <= hash2;
							end 
								else begin
									if(j == 8'd3)begin
										present_write_data <= hash3;
									end
										else begin
                                if(j == 8'd4)begin
												present_write_data <= hash4;
                                end
												else begin
													if(j == 8'd5)begin
														present_write_data <= hash5;
													end
														else begin
															if(j == 8'd6)begin
																present_write_data <= hash6;
															end
															else begin
																if(j == 8'd7)begin
																	present_write_data <= hash7;
																end
																else begin
																	present_write_data <= 32'd0;
																end
															end
														end
													end
												end
											end
										end
									end
								state <= WR_PULSE;
							end
				WR_PULSE: begin
					enable_write <= 1'b1;
					state <= WR_HOLD;
            end
				
            WR_HOLD: begin
                enable_write <= 1'b0;
                state <= WR_NEXT;
            end
				
            WR_NEXT: begin
                if(j == 8'd7)begin
                    state <= IDLE;
                end
					 else begin
						j <= j + 8'd1;
						state <= WRITE;
                end
					end
					
				// Generate done when SHA256 hash computation has finished and moved to IDLE state
            default: begin
                state <= IDLE;
            end
        endcase
    end
end
endmodule


