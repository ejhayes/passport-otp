var otp = require('index');


describe('passport-otp', function() {
    
  it('should export version', function() {
    expect(otp.version).to.be.a('string');
  });
    
  it('should export Strategy', function() {
    expect(otp.Strategy).to.be.a('function');
  });
  
});
