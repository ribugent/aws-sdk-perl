# Generated by default/object.tt
package Paws::Lambda::CodeSigningConfig;
  use Moose;
  has AllowedPublishers => (is => 'ro', isa => 'Paws::Lambda::AllowedPublishers', required => 1);
  has CodeSigningConfigArn => (is => 'ro', isa => 'Str', required => 1);
  has CodeSigningConfigId => (is => 'ro', isa => 'Str', required => 1);
  has CodeSigningPolicies => (is => 'ro', isa => 'Paws::Lambda::CodeSigningPolicies', required => 1);
  has Description => (is => 'ro', isa => 'Str');
  has LastModified => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Lambda::CodeSigningConfig

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Lambda::CodeSigningConfig object:

  $service_obj->Method(Att1 => { AllowedPublishers => $value, ..., LastModified => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Lambda::CodeSigningConfig object:

  $result = $service_obj->Method(...);
  $result->Att1->AllowedPublishers

=head1 DESCRIPTION

Details about a Code signing configuration
(https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html).

=head1 ATTRIBUTES


=head2 B<REQUIRED> AllowedPublishers => L<Paws::Lambda::AllowedPublishers>

List of allowed publishers.


=head2 B<REQUIRED> CodeSigningConfigArn => Str

The Amazon Resource Name (ARN) of the Code signing configuration.


=head2 B<REQUIRED> CodeSigningConfigId => Str

Unique identifer for the Code signing configuration.


=head2 B<REQUIRED> CodeSigningPolicies => L<Paws::Lambda::CodeSigningPolicies>

The code signing policy controls the validation failure action for
signature mismatch or expiry.


=head2 Description => Str

Code signing configuration description.


=head2 B<REQUIRED> LastModified => Str

The date and time that the Code signing configuration was last
modified, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Lambda>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

