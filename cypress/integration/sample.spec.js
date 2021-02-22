describe('Demo Test Suite', () => {

  it('Visit Normal HTTPS website', () => {
    cy.visit('https://example.cypress.io');
  });

  it('Visit Simple PKI protected server using PEM/Key (wildcard)', () => {
    cy.visit('/whoami/');
    cy.contains(`{"CN":"user_pem","OU":"Users","O":"Cypress"}`);
  });

  it('Visit Simple PKI protected server using PFX/Passphrase (specific url)', () => {
    cy.visit('/whoami/pfx');
    cy.contains(`{"CN":"user_pfx","OU":"Users","O":"Cypress"}`);
  });

  it('Visit PKI Protected server containing sub-resources', () => {
    cy.visit('/logo/pem');
    cy.contains("Hello World");
    cy.get('[alt="Cypress Logo"]')
      .should('be.visible')
      .and(($img) => {
        expect($img[0].naturalWidth).to.be.greaterThan(0)
        expect($img[0].naturalHeight).to.be.greaterThan(0)
      })
  });
  
  it('Visit PKI Protected server and make request elsewhere (using different certificate)', () => {
    cy.visit('/logo/pem');
    cy.request("/whoami/pfx").its('body').should('contain', `{"CN":"user_pfx","OU":"Users","O":"Cypress"}`);
  });

})