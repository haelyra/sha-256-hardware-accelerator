module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

logic [ 4:0] state;
logic [31:0] hout[num_nonces];

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here

typedef enum logic [4:0] {IDLE, HDR_ADDR, HDR_WAIT, HDR_CAP,
    PH1_INIT,
    PH1_ROUND,
    PH1_DONE,
    PH2_INIT,
    PH2_ROUND,
    PH2_DONE,
    PH3_INIT,
    PH3_ROUND,
    PH3_DONE,
    WR_SETUP,
    WR_PULSE,
    WR_HOLD,
    NEXT_NONCE
}state_t;

//state_t state;

logic [31:0] header[0:18];
logic [7:0] hdr_idx, round_idx;
logic [31:0] nonce;
logic [31:0] wbuf[0:15];
logic [31:0] base0, base1, base2, base3, base4, base5, base6, base7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [31:0] fh0, fh1, fh2, fh3, fh4, fh5, fh6, fh7;
logic [31:0] ph2_0, ph2_1, ph2_2, ph2_3, ph2_4, ph2_5, ph2_6, ph2_7;
logic [31:0] final0;
logic we_r;
logic [15:0] addr_r;
logic [31:0] wdata_r;

assign mem_clk = clk;
assign mem_we = we_r;
assign mem_addr = addr_r;
assign mem_write_data = wdata_r;


function logic [31:0] ror(input logic [31:0] in, input logic [7:0] s);
	logic [31:0] a1, a2;
	begin
		a1=(in>>s);
		a2=(in<<(8'd32-s));
		ror=(a1|a2);
end
endfunction


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

always_comb begin
    if (state == IDLE) begin
        done = 1'b1;
    end else begin
        done = 1'b0;
    end
end


always_ff @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin

        state <= IDLE;
        hdr_idx <= 8'd0;
        round_idx <= 8'd0;
        nonce <= 32'd0;

        we_r <= 1'b0;
        addr_r <= 16'd0;
        wdata_r <= 32'd0;

        base0 <= 32'd0; base1 <= 32'd0; 
        base2 <= 32'd0; base3 <= 32'd0;
        base4 <= 32'd0; base5 <= 32'd0; 
        base6 <= 32'd0; base7 <= 32'd0;

        a <= 32'd0; b <= 32'd0; 
        c <= 32'd0; d <= 32'd0;
        e <= 32'd0; f <= 32'd0; 
        g <= 32'd0; h <= 32'd0;

        fh0 <= 32'd0; fh1 <= 32'd0; 
        fh2 <= 32'd0; fh3 <= 32'd0;
        fh4 <= 32'd0; fh5 <= 32'd0; 
        fh6 <= 32'd0; fh7 <= 32'd0;
        ph2_0 <= 32'd0; ph2_1 <= 32'd0; 
        ph2_2 <= 32'd0; ph2_3 <= 32'd0;
        ph2_4 <= 32'd0; ph2_5 <= 32'd0;
        ph2_6 <= 32'd0; ph2_7 <= 32'd0;

        final0 <= 32'd0;

        for (int i0 = 0; i0 < 19; i0 = i0 + 1) begin
            header[i0] <= 32'd0;
        end

        for (int i1 = 0; i1 < 16; i1 = i1 + 1) begin
            wbuf[i1] <= 32'd0;
        end

        

    end else begin

        case (state)


            IDLE: begin
                we_r <= 1'b0;
                addr_r <= 16'd0;
                wdata_r <= 32'd0;

                if (start == 1'b1) begin
                    hdr_idx <= 8'd0;
                    nonce <= 32'd0;
                    state <= HDR_ADDR;
                end else begin
                    state <= IDLE;
                end
            end

            HDR_ADDR: begin
                we_r <= 1'b0;
                addr_r <= message_addr + {8'd0, hdr_idx};
                state <= HDR_WAIT;
            end

            HDR_WAIT: begin
                state <= HDR_CAP;
            end

            HDR_CAP: begin
                header[hdr_idx] <= mem_read_data;
                if (hdr_idx == 8'd18) begin
                    state <= PH1_INIT;
                end else begin
                    hdr_idx <= hdr_idx + 8'd1;
                    state <= HDR_ADDR;
                end
            end

            PH1_INIT: begin
                for (int j0 = 0; j0 < 16; j0 = j0 + 1) begin
                    wbuf[j0] <= header[j0];
                end

                base0 <= 32'h6a09e667; base1 <= 32'hbb67ae85; base2 <= 32'h3c6ef372; base3 <= 32'ha54ff53a;
                base4 <= 32'h510e527f; base5 <= 32'h9b05688c; base6 <= 32'h1f83d9ab; base7 <= 32'h5be0cd19;

                a <= 32'h6a09e667; b <= 32'hbb67ae85; c <= 32'h3c6ef372; d <= 32'ha54ff53a;
                e <= 32'h510e527f; f <= 32'h9b05688c; g <= 32'h1f83d9ab; h <= 32'h5be0cd19;

                round_idx <= 8'd0;
                state <= PH1_ROUND;
            end

            PH1_ROUND: begin
                logic [31:0] wt, s0v, s1v, wtnew;
                logic [255:0] nxt;

                wt = wbuf[0];
                s0v = ror(wbuf[1], 8'd7) ^ ror(wbuf[1], 8'd18) ^ (wbuf[1] >> 3);
                s1v = ror(wbuf[14], 8'd17) ^ ror(wbuf[14], 8'd19) ^ (wbuf[14] >> 10);
                wtnew = wbuf[0] + s0v + wbuf[9] + s1v;

                nxt = sha256_op(a, b, c, d, e, f, g, h, wt, round_idx);

                a <= nxt[255:224];
                b <= nxt[223:192];
                c <= nxt[191:160];
                d <= nxt[159:128];
                e <= nxt[127:96];
                f <= nxt[95:64];
                g <= nxt[63:32];
                h <= nxt[31:0];

                if (round_idx != 8'd63) begin
                    for (int sh0 = 0; sh0 < 15; sh0 = sh0 + 1) begin
                        wbuf[sh0] <= wbuf[sh0 + 1];
                    end
                    wbuf[15] <= wtnew;
                    round_idx <= round_idx + 8'd1;
                    state <= PH1_ROUND;
                end else begin
                    state <= PH1_DONE;
                end
            end

            PH1_DONE: begin

                fh0 <= base0 + a;
                fh1 <= base1 + b;
                fh2 <= base2 + c;
                fh3 <= base3 + d;
                fh4 <= base4 + e;
                fh5 <= base5 + f;
                fh6 <= base6 + g;
                fh7 <= base7 + h;
                state <= PH2_INIT;
            end

            PH2_INIT: begin

                wbuf[0] <= header[16];
                wbuf[1] <= header[17];
                wbuf[2] <= header[18];
                wbuf[3] <= nonce;
                wbuf[4] <= 32'h80000000;


                for (int z0 = 5; z0 < 15; z0 = z0 + 1) begin
                    wbuf[z0] <= 32'h00000000;
                end
                wbuf[15] <= 32'd640;

                base0 <= fh0; 
                base1 <= fh1; 
                base2 <= fh2; 
                base3 <= fh3;
                base4 <= fh4;
                base5 <= fh5; 
                base6 <= fh6; 
                base7 <= fh7;


                a <= fh0; 
                b <= fh1; 
                c <= fh2; 
                d <= fh3;
                e <= fh4; 
                f <= fh5; 
                g <= fh6; 
                h <= fh7;

                round_idx <= 8'd0;
                state <= PH2_ROUND;


            end

            PH2_ROUND: begin //
                logic [31:0] wt, s0v, s1v, wtnew;
                logic [255:0] nxt;

                wt = wbuf[0];
                s0v = ror(wbuf[1], 8'd7) ^ ror(wbuf[1], 8'd18) ^ (wbuf[1] >> 3);
                s1v = ror(wbuf[14], 8'd17) ^ ror(wbuf[14], 8'd19) ^ (wbuf[14] >> 10);
                wtnew = wbuf[0] + s0v + wbuf[9] + s1v;

                nxt = sha256_op(a, b, c, d, e, f, g, h, wt, round_idx);

                a <= nxt[255:224];
                b <= nxt[223:192];
                c <= nxt[191:160];
                d <= nxt[159:128];
                e <= nxt[127:96];
                f <= nxt[95:64];
                g <= nxt[63:32];
                h <= nxt[31:0];

                if (round_idx != 8'd63) begin
                    for (int sh1 = 0; sh1 < 15; sh1 = sh1 + 1) begin
                        wbuf[sh1] <= wbuf[sh1 + 1];
                    end
                    wbuf[15] <= wtnew;
                    round_idx <= round_idx + 8'd1;
                    state <= PH2_ROUND;
                end else begin
                    state <= PH2_DONE;
                end
            end

            PH2_DONE: begin

                ph2_0 <= base0 + a;
                ph2_1 <= base1 + b;
                ph2_2 <= base2 + c;
                ph2_3 <= base3 + d;
                ph2_4 <= base4 + e;
                ph2_5 <= base5 + f;
                ph2_6 <= base6 + g;
                ph2_7 <= base7 + h;
                state <= PH3_INIT;

            end

            PH3_INIT: begin
            
                wbuf[0] <= ph2_0;
                wbuf[1] <= ph2_1;
                wbuf[2] <= ph2_2;
                wbuf[3] <= ph2_3;
                wbuf[4] <= ph2_4;
                wbuf[5] <= ph2_5;
                wbuf[6] <= ph2_6;
                wbuf[7] <= ph2_7;
                wbuf[8] <= 32'h80000000;

                for (int z1 = 9; z1 < 15; z1 = z1 + 1) begin
                    wbuf[z1] <= 32'h00000000;
                end


                wbuf[15] <= 32'd256;

                base0 <= 32'h6a09e667; base1 <= 32'hbb67ae85; 
                base2 <= 32'h3c6ef372; base3 <= 32'ha54ff53a;
                base4 <= 32'h510e527f; base5 <= 32'h9b05688c; 
                base6 <= 32'h1f83d9ab; base7 <= 32'h5be0cd19;
                a <= 32'h6a09e667; b <= 32'hbb67ae85; 
                c <= 32'h3c6ef372; d <= 32'ha54ff53a;
                e <= 32'h510e527f; f <= 32'h9b05688c; 
                g <= 32'h1f83d9ab; h <= 32'h5be0cd19;

                round_idx <= 8'd0;
                state <= PH3_ROUND;



            end

            PH3_ROUND: begin
                logic [31:0] wt, s0v, s1v, wtnew;
                logic [255:0] nxt;

                wt = wbuf[0];
                s0v = ror(wbuf[1], 8'd7) ^ ror(wbuf[1], 8'd18) ^ (wbuf[1] >> 3);
                s1v = ror(wbuf[14], 8'd17) ^ ror(wbuf[14], 8'd19) ^ (wbuf[14] >> 10);
                wtnew = wbuf[0] + s0v + wbuf[9] + s1v;

                nxt = sha256_op(a, b, c, d, e, f, g, h, wt, round_idx);

                a <= nxt[255:224];
                b <= nxt[223:192];  
                c <= nxt[191:160];
                d <= nxt[159:128];
                e <= nxt[127:96];
                f <= nxt[95:64];
                g <= nxt[63:32];
                h <= nxt[31:0];

                if (round_idx != 8'd63) begin
                    for (int sh2 = 0; sh2 < 15; sh2 = sh2 + 1) begin
                        wbuf[sh2] <= wbuf[sh2 + 1];
                    end
                    wbuf[15] <= wtnew;
                    round_idx <= round_idx + 8'd1;
                    state <= PH3_ROUND;
                end else begin

                    state <= PH3_DONE;
                end
            end

            PH3_DONE: begin
                final0 <= base0 + a;
                state <= WR_SETUP;
            end

            WR_SETUP: begin
                we_r <= 1'b0;
                addr_r <= output_addr + nonce[15:0];
                wdata_r <= final0;
                state <= WR_PULSE;
            end

            WR_PULSE: begin
                we_r <= 1'b1;
                state <= WR_HOLD; 
            end

            WR_HOLD: begin
                we_r <= 1'b0;
                state <= NEXT_NONCE;
            end

            NEXT_NONCE: begin
                if (nonce == (num_nonces - 1)) begin
                    state <= IDLE;
                end else begin
                    nonce <= nonce + 32'd1;
                    state <= PH2_INIT;
                end

            end

            default: begin
                state <= IDLE;
            end

        endcase
    end



end

endmodule
