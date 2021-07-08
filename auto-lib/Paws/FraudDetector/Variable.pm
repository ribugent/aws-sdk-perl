# Generated by default/object.tt
package Paws::FraudDetector::Variable;
  use Moose;
  has Arn => (is => 'ro', isa => 'Str', request_name => 'arn', traits => ['NameInRequest']);
  has CreatedTime => (is => 'ro', isa => 'Str', request_name => 'createdTime', traits => ['NameInRequest']);
  has DataSource => (is => 'ro', isa => 'Str', request_name => 'dataSource', traits => ['NameInRequest']);
  has DataType => (is => 'ro', isa => 'Str', request_name => 'dataType', traits => ['NameInRequest']);
  has DefaultValue => (is => 'ro', isa => 'Str', request_name => 'defaultValue', traits => ['NameInRequest']);
  has Description => (is => 'ro', isa => 'Str', request_name => 'description', traits => ['NameInRequest']);
  has LastUpdatedTime => (is => 'ro', isa => 'Str', request_name => 'lastUpdatedTime', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest']);
  has VariableType => (is => 'ro', isa => 'Str', request_name => 'variableType', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::FraudDetector::Variable

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::FraudDetector::Variable object:

  $service_obj->Method(Att1 => { Arn => $value, ..., VariableType => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::FraudDetector::Variable object:

  $result = $service_obj->Method(...);
  $result->Att1->Arn

=head1 DESCRIPTION

The variable.

=head1 ATTRIBUTES


=head2 Arn => Str

The ARN of the variable.


=head2 CreatedTime => Str

The time when the variable was created.


=head2 DataSource => Str

The data source of the variable.


=head2 DataType => Str

The data type of the variable. For more information see Variable types
(https://docs.aws.amazon.com/frauddetector/latest/ug/create-a-variable.html#variable-types).


=head2 DefaultValue => Str

The default value of the variable.


=head2 Description => Str

The description of the variable.


=head2 LastUpdatedTime => Str

The time when variable was last updated.


=head2 Name => Str

The name of the variable.


=head2 VariableType => Str

The variable type of the variable.

Valid Values: C<AUTH_CODE | AVS | BILLING_ADDRESS_L1 |
BILLING_ADDRESS_L2 | BILLING_CITY | BILLING_COUNTRY | BILLING_NAME |
BILLING_PHONE | BILLING_STATE | BILLING_ZIP | CARD_BIN | CATEGORICAL |
CURRENCY_CODE | EMAIL_ADDRESS | FINGERPRINT | FRAUD_LABEL |
FREE_FORM_TEXT | IP_ADDRESS | NUMERIC | ORDER_ID | PAYMENT_TYPE |
PHONE_NUMBER | PRICE | PRODUCT_CATEGORY | SHIPPING_ADDRESS_L1 |
SHIPPING_ADDRESS_L2 | SHIPPING_CITY | SHIPPING_COUNTRY | SHIPPING_NAME
| SHIPPING_PHONE | SHIPPING_STATE | SHIPPING_ZIP | USERAGENT>



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::FraudDetector>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

