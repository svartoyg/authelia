
import { MailSenderBuilder } from "../../src/lib/notifiers/MailSenderBuilder";
import Nodemailer = require("nodemailer");
import Sinon = require("sinon");
import Assert = require("assert");

describe("test MailSenderBuilder", function() {
  let createTransportStub: Sinon.SinonStub;
  beforeEach(function() {
    createTransportStub = Sinon.stub(Nodemailer, "createTransport");
  });

  afterEach(function() {
    createTransportStub.restore();
  });

  it("should create a gmail mail sender", function() {
    const mailSenderBuilder = new MailSenderBuilder(Nodemailer);
    mailSenderBuilder.buildGmail({
      username: "user_gmail",
      password: "pass_gmail",
      sender: "admin@example.com"
    });
    Assert.equal(createTransportStub.getCall(0).args[0].auth.user, "user_gmail");
    Assert.equal(createTransportStub.getCall(0).args[0].auth.pass, "pass_gmail");
  });

  it("should create a smtp mail sender", function() {
    const mailSenderBuilder = new MailSenderBuilder(Nodemailer);
    mailSenderBuilder.buildSmtp({
      host: "mail.example.com",
      password: "password",
      port: 25,
      secure: true,
      username: "user",
      sender: "admin@example.com"
    });
    Assert.deepStrictEqual(createTransportStub.getCall(0).args[0], {
      host: "mail.example.com",
      auth: {
        pass: "password",
        user: "user"
      },
      port: 25,
      secure: true,
    });
  });
});