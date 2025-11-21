// Platform image tilt effect - follows cursor position
document.addEventListener('DOMContentLoaded', function() {
  const platformImage = document.getElementById('platform-image');
  
  if (!platformImage) return;
  
  const container = platformImage.parentElement;
  const maxTilt = 2; // Maximum tilt angle in degrees
  const perspective = 1000; // 3D perspective
  
  container.addEventListener('mousemove', function(e) {
    const rect = container.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    // Calculate center of container
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    
    // Calculate offset from center (-1 to 1)
    const offsetX = (x - centerX) / centerX;
    const offsetY = (y - centerY) / centerY;
    
    // Calculate tilt angles (invert Y for natural feel)
    const rotateY = offsetX * maxTilt;
    const rotateX = -offsetY * maxTilt;
    
    // Apply transform
    platformImage.style.transform = `perspective(${perspective}px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
  });
  
  container.addEventListener('mouseleave', function() {
    // Reset to original position
    platformImage.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
  });
  
  // Add smooth transition when mouse leaves
  platformImage.style.transition = 'transform 0.3s ease-out';
});

