from PIL import Image, ImageDraw
import os


def create_cryptoz_icon():
    """Create CryptoZ icon matching the SVG design"""
    try:
        # Create assets directory
        os.makedirs("assets", exist_ok=True)
        
        # Sizes for ICO file
        icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        icon_images = []
        
        for size in icon_sizes:
            img = Image.new('RGBA', size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            scale = size[0] / 100.0  # Your SVG is 100x100
            
            # Colors from your SVG
            primary_blue = (26, 115, 232)  # #1a73e8
            light_blue = (26, 115, 232, 25)  # With opacity
            shield_blue = (26, 115, 232, 38)
            
            # 1. Background circle
            bg_radius = 45 * scale
            draw.ellipse(
                [size[0]/2 - bg_radius, size[1]/2 - bg_radius,
                 size[0]/2 + bg_radius, size[1]/2 + bg_radius],
                fill=light_blue,
                outline=primary_blue,
                width=max(1, int(2*scale))
            )
            
            # 2. Shield shape
            if size[0] >= 32:
                shield_top = 20 * scale
                shield_bottom = 80 * scale
                shield_left = 30 * scale
                shield_right = 70 * scale
                
                shield_points = [
                    (size[0]/2, shield_top),                    # Top center
                    (shield_right, shield_top + 10*scale),      # Right top
                    (shield_right, 50*scale),                   # Right middle
                    (size[0]/2, shield_bottom),                 # Bottom center  
                    (shield_left, 50*scale),                    # Left middle
                    (shield_left, shield_top + 10*scale)        # Left top
                ]
                
                draw.polygon(shield_points, fill=shield_blue, outline=primary_blue)
            
            # 3. Lock system
            if size[0] >= 24:
                # Lock base (vertical part)
                lock_x = size[0]/2 - 10*scale
                lock_y = 45*scale
                lock_width = 20*scale
                lock_height = 25*scale
                
                draw.rounded_rectangle(
                    [lock_x, lock_y, lock_x + lock_width, lock_y + lock_height],
                    radius=3*scale,
                    fill=primary_blue
                )
                
                # Lock body (horizontal part)
                if size[0] >= 32:
                    body_x = size[0]/2 - 15*scale
                    body_y = 50*scale
                    body_width = 30*scale
                    body_height = 20*scale
                    
                    draw.rounded_rectangle(
                        [body_x, body_y, body_x + body_width, body_y + body_height],
                        radius=5*scale,
                        fill=(26, 115, 232, 204)  # 80% opacity
                    )
                
                # Keyhole
                if size[0] >= 32:
                    keyhole_radius = 5*scale
                    keyhole_center = (size[0]/2, 55*scale)
                    
                    draw.ellipse(
                        [keyhole_center[0] - keyhole_radius, keyhole_center[1] - keyhole_radius,
                         keyhole_center[0] + keyhole_radius, keyhole_center[1] + keyhole_radius],
                        fill=(255, 255, 255)
                    )
            
            # 4. Binary code representation
            if size[0] >= 48:
                _draw_binary_pattern(draw, size, scale)
            
            icon_images.append(img)
        
        # Save files
        icon_images[0].save("assets/icon.ico", format="ICO", sizes=icon_sizes, append_images=icon_images[1:])
        icon_images[-1].save("assets/icon.png", "PNG", optimize=True)
        
        print("✅ CryptoZ icons created successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def _draw_binary_pattern(draw, size, scale):
    """Draw binary pattern instead of text"""
    # Top pattern: 1010 1101
    top_binary = "10101101"
    top_y = 38 * scale
    
    # Bottom pattern: 0101 0011  
    bottom_binary = "01010011"
    bottom_y = 68 * scale
    
    # Draw patterns
    _draw_binary_line(draw, size, scale, top_binary, top_y)
    _draw_binary_line(draw, size, scale, bottom_binary, bottom_y)


def _draw_binary_line(draw, size, scale, binary_str, y_pos):
    """Draw a line of binary pattern"""
    pattern_width = len(binary_str) * 3 * scale
    start_x = size[0]/2 - pattern_width/2
    
    for i, bit in enumerate(binary_str):
        x_pos = start_x + i * 3 * scale
        
        if bit == '1':
            # Draw a small square for '1'
            square_size = 2 * scale
            draw.rectangle(
                [x_pos, y_pos - square_size/2,
                 x_pos + square_size, y_pos + square_size/2],
                fill=(26, 115, 232, 178)  # Semi-transparent blue
            )
        else:
            # Draw a small dot for '0' 
            dot_size = 1 * scale
            draw.ellipse(
                [x_pos, y_pos - dot_size/2,
                 x_pos + dot_size, y_pos + dot_size/2],
                fill=(26, 115, 232, 128)  # More transparent
            )


if __name__ == "__main__":
    create_cryptoz_icon()